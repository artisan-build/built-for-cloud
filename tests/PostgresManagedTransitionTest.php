<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\ManagedTransition;
use ArtisanBuild\BuiltForCloud\ManagedTransitionStatus;
use ArtisanBuild\BuiltForCloud\Tests\Support\PostgresLane;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Symfony\Component\Process\Process;

uses(PostgresLane::class)->group('pgsql');

/** @param array<string, mixed> $input */
function p4bPgStartWorker(array $input): Process
{
    $process = new Process([PHP_BINARY, __DIR__.'/Fixtures/managed-transition-worker.php']);
    $process->setInput(json_encode($input, JSON_THROW_ON_ERROR));
    $process->start();

    return $process;
}

/** @return array<string, mixed> */
function p4bPgFinishWorker(Process $process): array
{
    $process->wait();
    expect($process->isSuccessful())->toBeTrue($process->getErrorOutput());

    if (! json_validate($process->getOutput())) {
        throw new RuntimeException('Transition worker returned invalid JSON: '.$process->getOutput().$process->getErrorOutput());
    }

    return json_decode($process->getOutput(), true, flags: JSON_THROW_ON_ERROR);
}

/** @param list<Process> $workers */
function p4bPgWaitForBlocked(array $workers, callable $count): void
{
    $deadline = microtime(true) + 30;

    while (microtime(true) < $deadline) {
        foreach ($workers as $worker) {
            if (! $worker->isRunning()) {
                throw new RuntimeException('Transition worker exited before the race barrier: '.$worker->getOutput().$worker->getErrorOutput());
            }
        }

        if ($count() === count($workers)) {
            return;
        }

        usleep(10_000);
    }

    throw new RuntimeException('Timed out waiting for transition workers at the database barrier.');
}

/** @param array<string, mixed> $overrides */
function p4bPgInsertTransition(array $overrides = []): ManagedTransition
{
    $requestId = str_repeat('r', 42).'1';
    $body = json_encode([
        'connection_id' => 'race-connection',
        'installation_id' => 'race-installation',
        'direction' => 'adopt',
        'transition_request_id' => $requestId,
    ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

    return ManagedTransition::query()->create([
        'id' => (string) Str::uuid(),
        'initiated_by_user_id' => '1',
        'direction' => 'adopt',
        'status' => 'preparing',
        'issuer' => 'https://issuer.example.test',
        'connection_id' => 'race-connection',
        'organization_id' => 'race-organization',
        'installation_id' => 'race-installation',
        'authority_base_url' => 'https://transition-authority.example.test',
        'authority_ca_bundle' => null,
        'client_credential_reference' => 'built-for-cloud.managed.client_secret',
        'mode_before' => 'standalone',
        'mode_after' => 'managed',
        'generation_before' => 7,
        'generation_after' => 8,
        'transition_request_id' => $requestId,
        'transition_id' => null,
        'prepare_request_body' => $body,
        'prepare_body_digest' => hash('sha256', $body),
        ...$overrides,
    ]);
}

it('lets the PostgreSQL active-slot index arbitrate concurrent prepares', function (
    bool $applicationCheck,
    string $secondDirection,
): void {
    $main = $this->postgresLaneConnection();
    $main->beginTransaction();
    $main->statement('LOCK TABLE bfc_managed_transitions IN SHARE MODE');
    $workers = [
        p4bPgStartWorker([
            'mode' => 'active-slot',
            'application_name' => 'bfc-p4b-active-a',
            'application_check' => $applicationCheck,
            'direction' => 'adopt',
            'request_id' => str_repeat('a', 43),
        ]),
        p4bPgStartWorker([
            'mode' => 'active-slot',
            'application_name' => 'bfc-p4b-active-b',
            'application_check' => $applicationCheck,
            'direction' => $secondDirection,
            'request_id' => str_repeat('b', 43),
        ]),
    ];

    try {
        p4bPgWaitForBlocked($workers, fn (): int => (int) $this->postgresLaneProbe()->scalar(<<<'SQL'
            select count(*)
            from pg_stat_activity
            where datname = current_database()
              and application_name like 'bfc-p4b-active-%'
              and state = 'active'
              and wait_event_type = 'Lock'
              and query like '%bfc_managed_transitions%'
            SQL));
        $main->commit();
        $results = array_map(p4bPgFinishWorker(...), $workers);
        $outcomes = array_column($results, 'result');
        sort($outcomes);
        $refusal = collect($results)->firstWhere('result', 'refused');

        expect($outcomes)->toBe(['inserted', 'refused'])
            ->and(ManagedTransition::query()->count())->toBe(1)
            ->and(json_encode($refusal['causes'] ?? [], JSON_THROW_ON_ERROR))->toContain('bfc_transition_active_slot_unique');
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
    'same direction with application check' => [true, 'adopt'],
    'opposite direction with application check' => [true, 'exit'],
    'positive control without application check' => [false, 'adopt'],
]);

it('does not turn the installation slot into an organization-wide freeze', function (): void {
    $main = $this->postgresLaneConnection();
    $main->beginTransaction();
    $main->statement('LOCK TABLE bfc_managed_transitions IN SHARE MODE');
    $workers = [
        p4bPgStartWorker([
            'mode' => 'active-slot',
            'application_name' => 'bfc-p4b-active-installation-a',
            'application_check' => true,
            'direction' => 'adopt',
            'request_id' => str_repeat('a', 43),
            'organization_id' => 'shared-organization',
            'installation_id' => 'installation-a',
        ]),
        p4bPgStartWorker([
            'mode' => 'active-slot',
            'application_name' => 'bfc-p4b-active-installation-b',
            'application_check' => true,
            'direction' => 'adopt',
            'request_id' => str_repeat('b', 43),
            'organization_id' => 'shared-organization',
            'installation_id' => 'installation-b',
        ]),
    ];

    try {
        p4bPgWaitForBlocked($workers, fn (): int => (int) $this->postgresLaneProbe()->scalar(<<<'SQL'
            select count(*)
            from pg_stat_activity
            where datname = current_database()
              and application_name like 'bfc-p4b-active-installation-%'
              and state = 'active'
              and wait_event_type = 'Lock'
              and query like '%bfc_managed_transitions%'
            SQL));
        $main->commit();
        $results = array_map(p4bPgFinishWorker(...), $workers);

        expect(array_column($results, 'result'))->toBe(['inserted', 'inserted'])
            ->and(ManagedTransition::query()->where('organization_id', 'shared-organization')->count())->toBe(2)
            ->and(ManagedTransition::query()->distinct('installation_id')->count('installation_id'))->toBe(2);
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

it('arbitrates the staged T7-versus-commit race with exactly one durable winner', function (): void {
    DB::table('bfc_authority')->updateOrInsert(
        ['key' => 'installation'],
        [
            'mode' => 'standalone',
            'generation' => 7,
            'issuer' => 'https://issuer.example.test',
            'connection_id' => 'race-connection',
            'organization_id' => 'race-organization',
            'installation_id' => 'race-installation',
            'authority_base_url' => 'https://transition-authority.example.test',
            'created_at' => now(),
            'updated_at' => now(),
        ],
    );
    $owner = User::query()->create(['name' => 'Race Owner', 'email' => 'race-owner@example.test']);
    $owner->forceFill(['role' => 'owner', 'status' => 'active'])->save();
    $transition = p4bPgInsertTransition([
        'status' => ManagedTransitionStatus::Staged,
        'transition_id' => 'authority-transition-race',
        'roster_version' => 41,
        'roster_cutoff_at' => '2026-09-11T12:00:00+00:00',
        'roster_total' => 1,
    ]);
    $main = $this->postgresLaneConnection();
    $main->beginTransaction();
    $main->table('bfc_managed_transitions')->where('id', $transition->id)->lockForUpdate()->first();
    $workers = [
        p4bPgStartWorker([
            'mode' => 'production-commit',
            'application_name' => 'bfc-p4b-cas-commit',
            'transition_id' => $transition->id,
        ]),
        p4bPgStartWorker([
            'mode' => 'production-abandon',
            'application_name' => 'bfc-p4b-cas-abandon',
            'transition_id' => $transition->id,
            'owner_id' => $owner->getKey(),
        ]),
    ];

    try {
        p4bPgWaitForBlocked($workers, fn (): int => (int) $this->postgresLaneProbe()->scalar(<<<'SQL'
            select count(*)
            from pg_stat_activity
            where datname = current_database()
              and application_name like 'bfc-p4b-cas-%'
              and state = 'active'
              and wait_event_type = 'Lock'
              and query like '%bfc_managed_transitions%'
            SQL));
        $main->commit();
        $results = array_map(p4bPgFinishWorker(...), $workers);
        $outcomes = array_column($results, 'result');
        sort($outcomes);
        $persisted = $transition->refresh();

        expect($outcomes)->toBeIn([
            ['abandoned', 'refused'],
            ['committed', 'refused'],
        ]);

        if ($persisted->status === ManagedTransitionStatus::Committed) {
            expect($persisted->local_commit_receipt)->toBeString()->not->toBeEmpty()
                ->and($persisted->abandon_idempotency_key)->toBeNull();
        } else {
            expect($persisted->status)->toBe(ManagedTransitionStatus::Abandoned)
                ->and($persisted->abandon_idempotency_key)->toBeString()->not->toBeEmpty()
                ->and($persisted->local_commit_receipt)->toBeNull();
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
});

it('replays persisted T1 octets in a second process whose serializer orders keys differently', function (): void {
    $transition = p4bPgInsertTransition();
    $result = p4bPgFinishWorker(p4bPgStartWorker([
        'mode' => 'byte-replay',
        'application_name' => 'bfc-p4b-byte-replay',
        'transition_id' => $transition->id,
    ]));

    expect($result['result'])->toBe('sent')
        ->and($result['sent'])->toBe($result['persisted'])
        ->and($result['rebuilt'])->not->toBe($result['persisted'])
        ->and(hash('sha256', $result['sent']))->toBe($transition->prepare_body_digest);
});

it('recovers each durable local state in a second process from T5 or T6 evidence', function (
    string $localStatus,
    string $authorityStatus,
    string $expectedStatus,
    int $expectedCalls,
): void {
    $transitionId = 'authority-transition-'.$localStatus;
    $stageKey = str_repeat('s', 43);
    $stageBody = json_encode([
        'connection_id' => 'race-connection',
        'installation_id' => 'race-installation',
        'idempotency_key' => $stageKey,
        'roster_version' => 41,
        'roster_cutoff_at' => '2026-09-11T12:00:00+00:00',
        'mapping' => [],
    ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    $receipt = str_repeat('r', 43);
    $ackKey = str_repeat('k', 43);
    $ackBody = json_encode([
        'connection_id' => 'race-connection',
        'installation_id' => 'race-installation',
        'idempotency_key' => $ackKey,
        'local_commit_receipt' => $receipt,
        'mode_after' => 'managed',
        'generation_after' => 8,
    ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    $preparing = $localStatus === 'preparing';
    $afterCommit = in_array($localStatus, ['committed', 'acknowledging'], true);
    DB::table('bfc_authority')->updateOrInsert(
        ['key' => 'installation'],
        [
            'mode' => $afterCommit ? 'managed' : 'standalone',
            'generation' => $afterCommit ? 8 : 7,
            'issuer' => 'https://issuer.example.test',
            'connection_id' => 'race-connection',
            'organization_id' => 'race-organization',
            'installation_id' => 'race-installation',
            'authority_base_url' => 'https://transition-authority.example.test',
            'created_at' => now(),
            'updated_at' => now(),
        ],
    );
    $transition = p4bPgInsertTransition([
        'status' => $localStatus,
        'transition_id' => $preparing ? null : $transitionId,
        'roster_version' => $preparing ? null : 41,
        'roster_cutoff_at' => $preparing ? null : '2026-09-11T12:00:00+00:00',
        'roster_total' => $preparing ? null : 1,
        'stage_idempotency_key' => $localStatus === 'staging' ? $stageKey : null,
        'stage_request_body' => $localStatus === 'staging' ? $stageBody : null,
        'stage_body_digest' => $localStatus === 'staging' ? hash('sha256', $stageBody) : null,
        'local_commit_receipt' => $afterCommit ? $receipt : null,
        'ack_idempotency_key' => $localStatus === 'acknowledging' ? $ackKey : null,
        'ack_request_body' => $localStatus === 'acknowledging' ? $ackBody : null,
        'ack_body_digest' => $localStatus === 'acknowledging' ? hash('sha256', $ackBody) : null,
    ]);
    $result = p4bPgFinishWorker(p4bPgStartWorker([
        'mode' => 'production-recover',
        'application_name' => 'bfc-p4b-recover-'.$localStatus,
        'transition_id' => $transition->id,
        'authority_status' => $authorityStatus,
    ]));

    expect($result['result'])->toBe($expectedStatus)
        ->and($result['calls'])->toHaveCount($expectedCalls)
        ->and($transition->refresh()->status->value)->toBe($expectedStatus);

    if ($localStatus === 'preparing') {
        expect($result['calls'][0]['path'])->toContain('/transition-requests/')
            ->and($result['calls'][1]['body'])->toBe($transition->prepare_request_body);
    }
    if ($localStatus === 'staging' && $authorityStatus === 'prepared') {
        expect($result['calls'][1]['body'])->toBe($stageBody)
            ->and($result['stage_key'])->toBe($stageKey);
    }
    if ($localStatus === 'acknowledging') {
        expect($result['calls'][1]['body'])->toBe($ackBody)
            ->and($result['ack_key'])->toBe($ackKey);
    }
})->with([
    'preparing via T6 then recorded T1' => ['preparing', 'prepared', 'prepared', 2],
    'prepared' => ['prepared', 'prepared', 'prepared', 1],
    'rostered' => ['rostered', 'prepared', 'rostered', 1],
    'proposed' => ['proposed', 'prepared', 'proposed', 1],
    'staging before authority execution' => ['staging', 'prepared', 'staged', 2],
    'staging after authority execution' => ['staging', 'staged', 'staged', 1],
    'staged before local commit' => ['staged', 'staged', 'staged', 1],
    'committed resends a new ack' => ['committed', 'staged', 'acknowledged', 2],
    'acknowledging replays recorded ack' => ['acknowledging', 'staged', 'acknowledged', 2],
]);

it('recovers a committed exit and acknowledges from standalone mode in a second process', function (): void {
    DB::table('bfc_authority')->updateOrInsert(
        ['key' => 'installation'],
        [
            'mode' => 'standalone',
            'generation' => 8,
            'issuer' => 'https://issuer.example.test',
            'connection_id' => 'race-connection',
            'organization_id' => 'race-organization',
            'installation_id' => 'race-installation',
            'authority_base_url' => 'https://transition-authority.example.test',
            'created_at' => now(),
            'updated_at' => now(),
        ],
    );
    $receipt = str_repeat('e', 43);
    $transition = p4bPgInsertTransition([
        'direction' => 'exit',
        'status' => 'committed',
        'mode_before' => 'managed',
        'mode_after' => 'standalone',
        'transition_id' => 'authority-exit-recovery',
        'roster_version' => 41,
        'roster_cutoff_at' => '2026-09-11T12:00:00+00:00',
        'roster_total' => 1,
        'local_commit_receipt' => $receipt,
    ]);
    $result = p4bPgFinishWorker(p4bPgStartWorker([
        'mode' => 'production-recover',
        'application_name' => 'bfc-p4b-recover-exit',
        'transition_id' => $transition->id,
        'authority_status' => 'staged',
    ]));
    $ackBody = json_decode($result['calls'][1]['body'], true, flags: JSON_THROW_ON_ERROR);

    expect($result['result'])->toBe('acknowledged')
        ->and($ackBody['mode_after'])->toBe('standalone')
        ->and($ackBody['local_commit_receipt'])->toBe($receipt)
        ->and($transition->refresh()->status)->toBe(ManagedTransitionStatus::Acknowledged);
});
