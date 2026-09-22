<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\Tests\Support\PostgresLane;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Support\Facades\DB;
use Symfony\Component\Process\Process;

uses(PostgresLane::class)->group('pgsql');

/**
 * Quality-review round 2, blocking finding 1: the disconnect ledger's
 * recorded binding must ride INTO transition creation and be compared
 * against the authority row under the same transaction and row lock
 * that persists the transition snapshot, so no lifecycle change can
 * interleave between the caller's validation and transition creation.
 *
 * Two deterministic schedules against one real PostgreSQL row lock:
 *
 * - Worker 1 parks ON the authority row lock inside prepare()'s
 *   transaction while the supported lifecycle commits a later binding
 *   over the row (the barrier is observed through pg_stat_activity).
 *   The locked validation must refuse the stale recorded binding and
 *   leave no transition row.
 * - Worker 2 runs AFTER the flip has committed: the fresh snapshot
 *   agrees with the row, so ONLY the caller's recorded expectation can
 *   refuse. This is the discriminating schedule — before the fix the
 *   worker snapshots the later binding and creates a transition for it.
 */
it('refuses a stale recorded binding from creating a transition across a concurrent lifecycle change', function (): void {
    DB::table('bfc_authority')->updateOrInsert(['key' => InstallationAuthority::KEY], [
        'mode' => 'managed',
        'generation' => 2,
        'issuer' => 'https://first-issuer.example.test',
        'connection_id' => 'first-connection',
        'organization_id' => 'first-organization',
        'installation_id' => 'first-installation',
        // Unroutable on purpose: any authority leg the guard wrongly
        // permits fails fast instead of hanging the worker.
        'authority_base_url' => 'https://127.0.0.1:1',
        'created_at' => now(),
        'updated_at' => now(),
    ]);
    $owner = User::query()->create(['name' => 'Atomicity Owner', 'email' => 'atomicity-owner@example.test']);
    $owner->forceFill(['role' => 'owner', 'status' => 'active'])->save();

    $workerInput = [
        'owner_email' => 'atomicity-owner@example.test',
        'client_secret' => 'atomicity-config-secret',
        'expected_issuer' => 'https://first-issuer.example.test',
        'expected_connection_id' => 'first-connection',
        'expected_installation_id' => 'first-installation',
        'expected_generation' => 2,
    ];
    $startWorker = static function (int $index) use ($workerInput): Process {
        $process = new Process([PHP_BINARY, __DIR__.'/Fixtures/managed-enrolment-transition-worker.php']);
        $process->setTimeout(null);
        $process->setInput(json_encode(['worker' => $index, ...$workerInput], JSON_THROW_ON_ERROR));
        $process->start();

        return $process;
    };
    $workerOutcome = static function (Process $process): array {
        $process->wait();

        if (! $process->isSuccessful()) {
            throw new RuntimeException('Worker failed: '.$process->getErrorOutput().$process->getOutput());
        }

        return json_decode($process->getOutput(), true, flags: JSON_THROW_ON_ERROR);
    };

    $main = $this->postgresLaneConnection();
    $main->beginTransaction();
    $main->table('bfc_authority')->where('key', InstallationAuthority::KEY)->lockForUpdate()->first();

    $first = $startWorker(1);

    try {
        $blocked = false;

        foreach (range(1, 5000) as $attempt) {
            $waiting = (int) $this->postgresLaneProbe()->scalar(<<<'SQL'
                select count(*)
                from pg_stat_activity
                where datname = current_database()
                  and application_name = 'bfc-p1-atomicity-worker-1'
                  and state = 'active'
                  and wait_event_type = 'Lock'
                  and query like '%bfc_authority%'
                SQL);

            if ($waiting === 1) {
                $blocked = true;

                break;
            }

            if (! $first->isRunning()) {
                throw new RuntimeException('The first worker exited before parking on the authority lock: '.$first->getOutput().$first->getErrorOutput());
            }
        }

        expect($blocked)->toBeTrue();

        // The supported lifecycle installs the later binding while the
        // stale retry is parked on the row lock.
        $main->table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
            'generation' => 4,
            'issuer' => 'https://later-issuer.example.test',
            'connection_id' => 'later-connection',
            'organization_id' => 'later-organization',
            'installation_id' => 'later-installation',
            'updated_at' => now(),
        ]);
        $main->commit();
    } catch (Throwable $failure) {
        if ($first->isRunning()) {
            $first->stop();
        }

        if ($main->transactionLevel() > 0) {
            $main->rollBack();
        }

        throw $failure;
    }

    $outcome = $workerOutcome($first);
    expect($outcome['refused'])->toBeTrue();

    // The discriminating schedule: the flip is already durable, so the
    // fresh snapshot agrees with the row and only the caller's recorded
    // expectation can refuse.
    $second = $startWorker(2);
    $outcomeTwo = $workerOutcome($second);

    expect($outcomeTwo['refused'])->toBeTrue()
        ->and(DB::table('bfc_managed_transitions')->count())->toBe(0)
        ->and((array) DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->sole())->toMatchArray([
            'mode' => 'managed',
            'generation' => 4,
            'issuer' => 'https://later-issuer.example.test',
            'connection_id' => 'later-connection',
            'organization_id' => 'later-organization',
            'installation_id' => 'later-installation',
        ]);
});
