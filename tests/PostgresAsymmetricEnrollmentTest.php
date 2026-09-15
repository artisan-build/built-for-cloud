<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\CompleteAsymmetricEnrollment;
use ArtisanBuild\BuiltForCloud\Actions\MintCredential;
use ArtisanBuild\BuiltForCloud\Actions\RotateCredential;
use ArtisanBuild\BuiltForCloud\AuditReason;
use ArtisanBuild\BuiltForCloud\BoundCredentialScope;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialOutboxEntry;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\MintOptions;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\RotateOptions;
use ArtisanBuild\BuiltForCloud\Rs256PublicKey;
use ArtisanBuild\BuiltForCloud\Tests\Support\PostgresLane;
use Illuminate\Support\Facades\DB;
use Symfony\Component\Process\Process;

uses(PostgresLane::class)->group('pgsql');

/** @return array{scope: BoundCredentialScope, code: string, id: string} */
function postgresPendingAsymmetricEnrollment(): array
{
    testsConfigureBoundPurposes();
    $scope = testsBoundScope();
    $mint = app(MintCredential::class)(
        $scope->subject,
        new MintOptions(
            kind: CredentialKind::Asymmetric,
            purpose: CredentialPurpose::Signing,
            codeTtlSeconds: 3600,
            boundScope: $scope,
        ),
    );

    return [
        'scope' => $scope,
        'code' => (string) $mint->secret?->reveal(),
        'id' => $mint->summary->id,
    ];
}

/** @return array<string, mixed> */
function postgresEnrollmentWorkerInput(int $worker, string $operation, array $pending, string $publicKey, ?string $sourceId = null): array
{
    return [
        'worker' => $worker,
        'operation' => $operation,
        'code' => $pending['code'],
        'public_key' => $publicKey,
        'source_id' => $sourceId,
        'app_purpose' => $pending['scope']->appPurpose,
        'subject_type' => $pending['scope']->subject->type->value,
        'subject_ref' => $pending['scope']->subject->ref,
        'installation' => $pending['scope']->installation,
        'application' => $pending['scope']->application,
        'audience' => $pending['scope']->audience,
    ];
}

/** @param list<Process> $workers */
function waitForEnrollmentWorkersToBlock(array $workers, $probe): void
{
    foreach (range(1, 5000) as $ignored) {
        foreach ($workers as $worker) {
            if (! $worker->isRunning()) {
                throw new RuntimeException('An enrollment worker exited before token-lock release: '.$worker->getOutput().$worker->getErrorOutput());
            }
        }

        $blocked = (int) $probe->scalar(<<<'SQL'
            select count(*)
            from pg_stat_activity
            where datname = current_database()
              and application_name like 'bfc-asymmetric-enrollment-worker-%'
              and state = 'active'
              and wait_event_type = 'Lock'
              and query like '%onboarding_tokens%'
            SQL);

        if ($blocked === count($workers)) {
            return;
        }
    }

    throw new RuntimeException('Enrollment workers did not reach the onboarding-token lock barrier.');
}

/** @param list<Process> $workers @return list<array<string, mixed>> */
function finishEnrollmentWorkers(array $workers): array
{
    $results = [];

    foreach ($workers as $worker) {
        $worker->wait();
        expect($worker->isSuccessful())->toBeTrue($worker->getErrorOutput());
        $results[] = json_decode($worker->getOutput(), true, flags: JSON_THROW_ON_ERROR);
    }

    return $results;
}

it('serializes two completion claimants at the token lock with one activation and audit winner', function (): void {
    $pending = postgresPendingAsymmetricEnrollment();
    $publicKey = testsRsaKey()['public'];
    $main = $this->postgresLaneConnection();
    $main->beginTransaction();
    $main->table('onboarding_tokens')->where('durable_credential_id', $pending['id'])->lockForUpdate()->sole();
    $workers = [];

    try {
        foreach ([1, 2] as $workerId) {
            $worker = new Process([PHP_BINARY, __DIR__.'/Fixtures/asymmetric-enrollment-worker.php']);
            $worker->setInput(json_encode(postgresEnrollmentWorkerInput($workerId, 'complete', $pending, $publicKey), JSON_THROW_ON_ERROR));
            $worker->start();
            $workers[] = $worker;
        }

        waitForEnrollmentWorkersToBlock($workers, $this->postgresLaneProbe());
        $main->commit();
        $results = finishEnrollmentWorkers($workers);

        expect(array_count_values(array_column($results, 'outcome')))->toBe(['completed' => 1, 'refused' => 1])
            ->and(Credential::query()->findOrFail($pending['id'])->status)->toBe(CredentialStatus::Active)
            ->and(OnboardingToken::query()->where('durable_credential_id', $pending['id'])->sole()->consumed_at)->not->toBeNull()
            ->and(CredentialAuditEvent::query()->where('credential_id', $pending['id'])->where('event', LifecycleEventType::Exchanged)->count())->toBe(1)
            ->and(CredentialAuditEvent::query()->where('credential_id', $pending['id'])->where('event', LifecycleEventType::Activated)->count())->toBe(1)
            ->and(CredentialOutboxEntry::query()->count())->toBe(3);
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

it('serializes completion against reissue under token credential UUID and binding lock order', function (): void {
    $source = postgresPendingAsymmetricEnrollment();
    app(CompleteAsymmetricEnrollment::class)($source['code'], $source['scope'], new Rs256PublicKey(testsRsaKey()['public']));
    $rotation = app(RotateCredential::class)($source['id'], new RotateOptions(codeTtlSeconds: 3600));
    $pending = [
        'scope' => $source['scope'],
        'code' => (string) $rotation?->mint->secret?->reveal(),
        'id' => (string) $rotation?->mint->summary->id,
    ];
    $main = $this->postgresLaneConnection();
    $main->beginTransaction();
    $main->table('onboarding_tokens')->where('durable_credential_id', $pending['id'])->lockForUpdate()->sole();
    $workers = [];

    try {
        foreach (['complete', 'reissue'] as $index => $operation) {
            $worker = new Process([PHP_BINARY, __DIR__.'/Fixtures/asymmetric-enrollment-worker.php']);
            $worker->setInput(json_encode(postgresEnrollmentWorkerInput(
                $index + 1,
                $operation,
                $pending,
                testsRsaKey()['public'],
                $source['id'],
            ), JSON_THROW_ON_ERROR));
            $worker->start();
            $workers[] = $worker;
        }

        waitForEnrollmentWorkersToBlock($workers, $this->postgresLaneProbe());
        $main->commit();
        $results = finishEnrollmentWorkers($workers);
        $outcomes = array_count_values(array_column($results, 'outcome'));

        expect($outcomes['refused'] ?? 0)->toBe(1)
            ->and(($outcomes['completed'] ?? 0) + ($outcomes['reissued'] ?? 0))->toBe(1)
            ->and(Credential::query()->where('status', CredentialStatus::Pending)->whereNull('revoked_at')->count())->toBe($outcomes['reissued'] ?? 0)
            ->and(CredentialAuditEvent::query()->where('credential_id', $pending['id'])->where('event', LifecycleEventType::Activated)->count())->toBe($outcomes['completed'] ?? 0)
            ->and(CredentialAuditEvent::query()->where('credential_id', $pending['id'])->where('reason_code', AuditReason::DeliveryAbandoned)->count())->toBe($outcomes['reissued'] ?? 0);
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
