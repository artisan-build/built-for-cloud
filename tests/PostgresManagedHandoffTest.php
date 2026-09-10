<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Tests\Support\PostgresLane;
use Illuminate\Support\Facades\DB;
use Symfony\Component\Process\Process;

uses(PostgresLane::class)->group('pgsql');

it('lets exactly one concurrent callback claim the BfC correlation and reach exchange', function (): void {
    $state = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    $sessionNonce = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    $connection = [
        'issuer' => 'https://issuer.example.test',
        'connection_id' => 'postgres-connection',
        'organization_id' => 'postgres-organization',
        'installation_id' => 'postgres-installation',
        'authority_generation' => 7,
        'base_url' => 'https://authority.example.test',
    ];
    DB::table('bfc_managed_handoffs')->insert([
        'state_hash' => hash('sha256', $state),
        'session_nonce_hash' => hash('sha256', $sessionNonce),
        'issuer' => $connection['issuer'],
        'connection_id' => $connection['connection_id'],
        'organization_id' => $connection['organization_id'],
        'installation_id' => $connection['installation_id'],
        'authority_generation' => $connection['authority_generation'],
        'expires_at' => now()->addMinute(),
        'consumed_at' => null,
        'created_at' => now(),
        'updated_at' => now(),
    ]);

    $main = $this->postgresLaneConnection();
    $main->beginTransaction();
    $main->table('bfc_managed_handoffs')->where('state_hash', hash('sha256', $state))->lockForUpdate()->first();
    $workers = [];

    foreach (range(1, 5) as $worker) {
        $process = new Process([PHP_BINARY, __DIR__.'/Fixtures/managed-handoff-claim-worker.php']);
        $process->setInput(json_encode(array_merge($connection, [
            'worker' => $worker,
            'state' => $state,
            'session_nonce' => $sessionNonce,
            'code' => bin2hex(random_bytes(16)),
        ]), JSON_THROW_ON_ERROR));
        $process->start();
        $workers[] = $process;
    }

    $allBlocked = false;

    foreach (range(1, 5000) as $attempt) {
        foreach ($workers as $process) {
            if (! $process->isRunning()) {
                throw new RuntimeException(
                    'A claim worker exited before the release: '.$process->getOutput().$process->getErrorOutput(),
                );
            }
        }

        $active = (int) $this->postgresLaneProbe()->scalar(<<<'SQL'
            select count(*)
            from pg_stat_activity
            where datname = current_database()
              and application_name like 'bfc-p3a-claim-worker-%'
              and state = 'active'
              and query like '%bfc_managed_handoffs%'
            SQL);

        if ($active === count($workers)) {
            $allBlocked = true;
            break;
        }
    }

    expect($allBlocked)->toBeTrue();
    $main->commit();
    $results = [];

    foreach ($workers as $process) {
        $process->wait();
        expect($process->isSuccessful())->toBeTrue($process->getErrorOutput());
        $results[] = json_decode($process->getOutput(), true, flags: JSON_THROW_ON_ERROR);
    }

    expect(array_filter($results, static fn (array $result): bool => $result['claimed']))->toHaveCount(1)
        ->and(array_filter($results, static fn (array $result): bool => $result['exchange_reached']))->toHaveCount(1)
        ->and(DB::table('bfc_managed_handoffs')->whereNotNull('consumed_at')->count())->toBe(1);
});
