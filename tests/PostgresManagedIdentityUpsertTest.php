<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\ManagedAuthConnection;
use ArtisanBuild\BuiltForCloud\ManagedAuthExchange;
use ArtisanBuild\BuiltForCloud\ManagedIdentityUpsert;
use ArtisanBuild\BuiltForCloud\Tests\Support\PostgresLane;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Database\QueryException;
use Symfony\Component\Process\Process;

uses(PostgresLane::class)->group('pgsql');

/** @param array<string, mixed> $overrides */
function startManagedIdentityWorker(int $worker, array $overrides = []): Process
{
    $process = new Process([PHP_BINARY, __DIR__.'/Fixtures/managed-identity-upsert-worker.php']);
    $process->setInput(json_encode(array_merge([
        'application_name' => 'bfc-p3b-upsert-worker-'.$worker,
        'issuer' => 'https://issuer.example.test',
        'connection_id' => 'connection-fixture',
        'subject' => 'subject-fixture',
        'email' => 'concurrent@example.test',
    ], $overrides), JSON_THROW_ON_ERROR));
    $process->start();

    return $process;
}

/** @return array<string, mixed> */
function finishManagedIdentityWorker(Process $process): array
{
    $process->wait();
    expect($process->isSuccessful())->toBeTrue($process->getErrorOutput());

    return json_decode($process->getOutput(), true, flags: JSON_THROW_ON_ERROR);
}

it('enforces normalized email uniqueness on a real case-sensitive PostgreSQL lane', function (): void {
    $caseSensitive = $this->postgresLaneConnection()->scalar("select 'CaseSensitive' = 'casesensitive'");
    expect($caseSensitive)->toBeFalse();

    User::query()->create(['name' => 'First', 'email' => 'CaseSensitive@example.test']);
    expect(fn () => User::query()->create(['name' => 'Second', 'email' => 'casesensitive@example.test']))
        ->toThrow(QueryException::class);
});

it('makes concurrent first entries for one subject converge on exactly one row', function (): void {
    $main = $this->postgresLaneConnection();
    $main->beginTransaction();
    $main->table('users')->insert([
        'name' => 'Source Holder',
        'email' => 'concurrent@example.test',
        'role' => 'member',
        'status' => 'active',
        'email_is_generated' => false,
        'created_at' => now(),
        'updated_at' => now(),
    ]);
    $workers = array_map(startManagedIdentityWorker(...), range(1, 5));

    try {
        $allBlocked = false;

        foreach (range(1, 5000) as $ignored) {
            foreach ($workers as $worker) {
                if (! $worker->isRunning()) {
                    throw new RuntimeException(
                        'An upsert worker exited before the source collision was released: '
                        .$worker->getOutput().$worker->getErrorOutput(),
                    );
                }
            }

            $blocked = (int) $this->postgresLaneProbe()->scalar(<<<'SQL'
                select count(*)
                from pg_stat_activity
                where datname = current_database()
                  and application_name like 'bfc-p3b-upsert-worker-%'
                  and state = 'active'
                  and wait_event_type = 'Lock'
                  and query like '%users%'
                SQL);

            if ($blocked === count($workers)) {
                $allBlocked = true;
                break;
            }
        }

        expect($allBlocked)->toBeTrue();
        $main->commit();
        $results = array_map(finishManagedIdentityWorker(...), $workers);
        $subjectRows = User::query()
            ->where('scalpels_issuer', 'https://issuer.example.test')
            ->where('scalpels_connection_id', 'connection-fixture')
            ->where('scalpels_id', 'subject-fixture')
            ->get();

        expect($subjectRows)->toHaveCount(1)
            ->and(array_unique(array_column($results, 'id')))->toBe([$subjectRows->sole()->getKey()])
            ->and(array_unique(array_column($results, 'email')))->toBe(['concurrent+bfc@example.test'])
            ->and(User::query()->count())->toBe(2);
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
});

it('makes case-equivalent concurrent candidates contend at the normalized index and retry apart', function (): void {
    $main = $this->postgresLaneConnection();
    $main->beginTransaction();
    $main->table('users')->insert([
        'name' => 'Source Holder',
        'email' => 'case-race@example.test',
        'role' => 'member',
        'status' => 'active',
        'email_is_generated' => false,
        'created_at' => now(),
        'updated_at' => now(),
    ]);
    $workers = [
        startManagedIdentityWorker(11, [
            'subject' => 'case-subject-a',
            'email' => 'Case-Race@example.test',
        ]),
        startManagedIdentityWorker(12, [
            'subject' => 'case-subject-b',
            'email' => 'case-race@example.test',
        ]),
    ];

    try {
        $allBlocked = false;

        foreach (range(1, 5000) as $ignored) {
            foreach ($workers as $worker) {
                if (! $worker->isRunning()) {
                    throw new RuntimeException(
                        'A case-race worker exited before the source collision was released: '
                        .$worker->getOutput().$worker->getErrorOutput(),
                    );
                }
            }

            $blocked = (int) $this->postgresLaneProbe()->scalar(<<<'SQL'
                select count(*)
                from pg_stat_activity
                where datname = current_database()
                  and application_name in ('bfc-p3b-upsert-worker-11', 'bfc-p3b-upsert-worker-12')
                  and state = 'active'
                  and wait_event_type = 'Lock'
                  and query like '%users%'
                SQL);

            if ($blocked === count($workers)) {
                $allBlocked = true;
                break;
            }
        }

        expect($allBlocked)->toBeTrue();
        $main->commit();
        $results = array_map(finishManagedIdentityWorker(...), $workers);
        $normalized = array_map(
            static fn (array $result): string => strtolower($result['email']),
            $results,
        );
        sort($normalized);

        expect($normalized)->toBe([
            'case-race+bfc-2@example.test',
            'case-race+bfc@example.test',
        ])->and(User::query()->whereIn('scalpels_id', ['case-subject-a', 'case-subject-b'])->count())->toBe(2);
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
});

it('reads renewed and cleared source-email conflict artifacts after fresh upserts in new processes', function (): void {
    User::query()->create(['name' => 'Initial Holder', 'email' => 'initial-process@example.test']);
    User::query()->create(['name' => 'Renewed Holder', 'email' => 'renewed-process@example.test']);
    $connection = new ManagedAuthConnection(
        'https://issuer.example.test',
        'connection-fixture',
        'organization-fixture',
        'installation-fixture',
        7,
        'https://authority.example.test',
        'fixture-client-secret',
        null,
    );
    $exchange = static fn (string $email): ManagedAuthExchange => new ManagedAuthExchange(
        'process-subject',
        'membership-fixture',
        'active',
        'active',
        'member',
        'Process Subject',
        $email,
        true,
        8,
        13,
        new DateTimeImmutable('2026-09-10T12:00:00+00:00'),
    );
    $user = app(ManagedIdentityUpsert::class)->upsert($connection, $exchange('initial-process@example.test'));
    $assignedEmail = $user->email;
    $rowCount = User::query()->count();

    $renewed = finishManagedIdentityWorker(startManagedIdentityWorker(21, [
        'subject' => 'process-subject',
        'email' => 'renewed-process@example.test',
    ]));
    expect($renewed['id'])->toBe($user->getKey())
        ->and($renewed['email'])->toBe($assignedEmail)
        ->and($renewed['original_contact_email'])->toBe('renewed-process@example.test')
        ->and($renewed['email_conflict_at'])->toBeString()
        ->and($renewed['email_conflict_source'])->toBe('renewed-process@example.test')
        ->and(User::query()->count())->toBe($rowCount);

    $cleared = finishManagedIdentityWorker(startManagedIdentityWorker(22, [
        'subject' => 'process-subject',
        'email' => 'clear-process@example.test',
    ]));
    expect($cleared['id'])->toBe($user->getKey())
        ->and($cleared['email'])->toBe($assignedEmail)
        ->and($cleared['original_contact_email'])->toBe('clear-process@example.test')
        ->and($cleared['email_conflict_at'])->toBeNull()
        ->and($cleared['email_conflict_source'])->toBeNull()
        ->and(User::query()->count())->toBe($rowCount);
});
