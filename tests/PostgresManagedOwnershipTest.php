<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\ManagedAuthConfirmation;
use ArtisanBuild\BuiltForCloud\ManagedAuthConnection;
use ArtisanBuild\BuiltForCloud\ManagedAuthExchange;
use ArtisanBuild\BuiltForCloud\ManagedMembershipResponses;
use ArtisanBuild\BuiltForCloud\Tests\Support\PostgresLane;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Support\Facades\DB;
use Symfony\Component\Process\Process;

uses(PostgresLane::class)->group('pgsql');

function p4aPgStartOwnerWorker(string $subject, string $mode): Process
{
    $process = new Process([PHP_BINARY, __DIR__.'/Fixtures/managed-owner-acquisition-worker.php']);
    $process->setInput(json_encode([
        'application_name' => 'bfc-p4a-owner-'.$mode.'-'.$subject,
        'subject' => $subject,
        'mode' => $mode,
    ], JSON_THROW_ON_ERROR));
    $process->start();

    return $process;
}

/** @return array<string, mixed> */
function p4aPgFinishOwnerWorker(Process $process): array
{
    $process->wait();
    expect($process->isSuccessful())->toBeTrue($process->getErrorOutput());

    if (! json_validate($process->getOutput())) {
        throw new RuntimeException(
            'Owner worker returned invalid JSON: '.$process->getOutput().$process->getErrorOutput(),
        );
    }

    return json_decode($process->getOutput(), true, flags: JSON_THROW_ON_ERROR);
}

it('lets the Owner-slot unique index arbitrate concurrent first logins', function (string $mode): void {
    DB::table('bfc_authority')->updateOrInsert(
        ['key' => InstallationAuthority::KEY],
        [
            'mode' => 'managed',
            'generation' => 7,
            'issuer' => 'https://issuer.example.test',
            'connection_id' => 'connection-fixture',
            'organization_id' => 'organization-fixture',
            'installation_id' => 'installation-fixture',
            'authority_base_url' => 'https://authority.example.test',
            'created_at' => now(),
            'updated_at' => now(),
        ],
    );
    $main = $this->postgresLaneConnection();
    $main->beginTransaction();
    $main->statement('LOCK TABLE users IN SHARE MODE');
    $workers = [
        p4aPgStartOwnerWorker('candidate-a', $mode),
        p4aPgStartOwnerWorker('candidate-b', $mode),
    ];

    try {
        $blocked = 0;

        foreach (range(1, 10000) as $attempt) {
            foreach ($workers as $worker) {
                if (! $worker->isRunning()) {
                    throw new RuntimeException(
                        'An Owner worker exited before both application checks were bypassed: '
                        .$worker->getOutput().$worker->getErrorOutput(),
                    );
                }
            }

            $blocked = (int) $this->postgresLaneProbe()->scalar(<<<'SQL'
                select count(*)
                from pg_stat_activity
                where datname = current_database()
                  and application_name like 'bfc-p4a-owner-%'
                  and state = 'active'
                  and wait_event_type = 'Lock'
                  and query like '%users%'
                SQL);

            if ($blocked === 2) {
                break;
            }
        }

        expect($blocked)->toBe(2);
        $main->commit();
        $results = array_map(p4aPgFinishOwnerWorker(...), $workers);
        $outcomes = array_column($results, 'result');
        sort($outcomes);
        $refusal = collect($results)->firstWhere('result', 'refused');
        $causeText = json_encode($refusal['causes'] ?? [], JSON_THROW_ON_ERROR);

        expect($outcomes)->toBe(['refused', 'seated'])
            ->and(User::query()->whereNotNull('owner_slot')->count())->toBe(1)
            ->and(User::query()->count())->toBe(1)
            ->and($causeText)->toContain('owner_slot');

        if ($mode === 'managed-response') {
            expect($refusal['message'])->toBe('managed_owner_transition_refused');
        }
    } finally {
        foreach ($workers as $worker) {
            if ($worker->isRunning()) {
                $worker->stop();
            }
        }

        if ($main->transactionLevel() > 0) {
            $main->rollBack();
        }
    }
})->with([
    'normal response path' => ['managed-response'],
    'positive control without the application check' => ['without-application-check'],
]);

it('retries a real PostgreSQL deadlock during Owner acquisition', function (string $leg): void {
    DB::table('bfc_authority')->updateOrInsert(
        ['key' => InstallationAuthority::KEY],
        [
            'mode' => 'managed',
            'generation' => 7,
            'issuer' => 'https://issuer.example.test',
            'connection_id' => 'connection-fixture',
            'organization_id' => 'organization-fixture',
            'installation_id' => 'installation-fixture',
            'authority_base_url' => 'https://127.0.0.1:1',
            'created_at' => now(),
            'updated_at' => now(),
        ],
    );
    $connection = new ManagedAuthConnection(
        'https://issuer.example.test',
        'connection-fixture',
        'organization-fixture',
        'installation-fixture',
        7,
        'https://127.0.0.1:1',
        'unused',
        null,
    );
    $subject = $leg === 'confirmation' ? User::query()->create([
        'name' => 'Deadlock Candidate',
        'email' => 'deadlock-candidate@example.test',
    ]) : null;

    if ($subject instanceof User) {
        $subject->forceFill([
            'role' => 'member',
            'status' => 'active',
            'scalpels_issuer' => 'https://issuer.example.test',
            'scalpels_connection_id' => 'connection-fixture',
            'scalpels_id' => 'deadlock-candidate',
            'managed_membership_status' => 'active',
            'managed_membership_role' => 'member',
            'managed_membership_generation' => 7,
            'managed_membership_roster_version' => 10,
            'managed_membership_response_sequence' => 10,
        ])->save();
    }
    DB::unprepared('CREATE SEQUENCE p4a_owner_deadlock_attempt');
    DB::unprepared(<<<'SQL'
        CREATE FUNCTION p4a_raise_owner_deadlock_once() RETURNS trigger AS $$
        BEGIN
            IF NEW.role = 'owner' AND nextval('p4a_owner_deadlock_attempt') = 1 THEN
                RAISE EXCEPTION 'forced Owner acquisition deadlock' USING ERRCODE = '40P01';
            END IF;

            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        SQL);
    DB::unprepared(<<<'SQL'
        CREATE TRIGGER p4a_owner_deadlock_once
        BEFORE INSERT OR UPDATE OF role ON users
        FOR EACH ROW EXECUTE FUNCTION p4a_raise_owner_deadlock_once()
        SQL);

    try {
        $result = $leg === 'confirmation'
            ? app(ManagedMembershipResponses::class)->applyConfirmation(
                $connection,
                $subject,
                new ManagedAuthConfirmation(
                    'deadlock-candidate',
                    'active',
                    'active',
                    'owner',
                    20,
                    20,
                    new DateTimeImmutable('2026-09-11T12:00:00+00:00'),
                ),
            )
            : app(ManagedMembershipResponses::class)->applyExchange(
                $connection,
                new ManagedAuthExchange(
                    'deadlock-candidate',
                    'deadlock-membership',
                    'active',
                    'active',
                    'owner',
                    'Deadlock Candidate',
                    'deadlock-candidate@example.test',
                    true,
                    20,
                    20,
                    new DateTimeImmutable('2026-09-11T12:00:00+00:00'),
                ),
            );

        expect($leg === 'confirmation' ? $result : $result instanceof User)->toBeTrue()
            ->and(User::query()->whereNotNull('owner_slot')->sole()->scalpels_id)->toBe('deadlock-candidate')
            ->and((int) DB::scalar('SELECT last_value FROM p4a_owner_deadlock_attempt'))->toBe(2);
    } finally {
        DB::unprepared('DROP TRIGGER IF EXISTS p4a_owner_deadlock_once ON users');
        DB::unprepared('DROP FUNCTION IF EXISTS p4a_raise_owner_deadlock_once()');
        DB::unprepared('DROP SEQUENCE IF EXISTS p4a_owner_deadlock_attempt');
    }
})->with(['confirmation', 'exchange']);
