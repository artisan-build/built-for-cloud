<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\DecideDeviceAuthorization;
use ArtisanBuild\BuiltForCloud\Actions\DecideLoopbackAuthorization;
use ArtisanBuild\BuiltForCloud\Actions\StartDeviceAuthorization;
use ArtisanBuild\BuiltForCloud\Actions\StartLoopbackAuthorization;
use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\BoundCredentialScope;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationOwnership;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationProfile;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\CredentialVerb;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\SubmissionNonce;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\DeviceFlowDeclaration;
use ArtisanBuild\BuiltForCloud\Tests\Support\PostgresLane;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Database\QueryException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Symfony\Component\Process\Process;

uses(PostgresLane::class)->group('pgsql');

/** @return array<string, mixed> */
function pgAuthorizationProfile(User $user, string $purpose, CredentialAuthorizationOwnership $ownership = CredentialAuthorizationOwnership::Personal): array
{
    $subject = $ownership === CredentialAuthorizationOwnership::Personal
        ? new Subject(SubjectType::UserPrincipal, 'postgres-user:'.$user->getKey())
        : new Subject(SubjectType::Installation, 'postgres-installation');

    return [
        'app_purpose' => $purpose,
        'subject_type' => $subject->type->value,
        'subject_ref' => $subject->ref,
        'installation' => 'postgres-installation',
        'application' => 'postgres-application',
        'audience' => 'postgres-audience.example.test',
        'ownership' => $ownership->value,
    ];
}

/** @param array<string, mixed> $profile */
function pgAuthorizationRequest(object $test, User $user, array $profile): Request
{
    DeviceFlowDeclaration::$profiles = [new CredentialAuthorizationProfile(
        $profile['app_purpose'],
        new BoundCredentialScope(
            $profile['app_purpose'],
            new Subject(SubjectType::from($profile['subject_type']), $profile['subject_ref']),
            $profile['installation'],
            $profile['application'],
            $profile['audience'],
        ),
        CredentialAuthorizationOwnership::from($profile['ownership']),
        [],
        null,
        600,
        5,
    )];
    DeviceFlowDeclaration::$resolvedSubject = DeviceFlowDeclaration::$profiles[0]->scope->subject;
    $test->actingAsVersioned($user, 'web');
    $request = request();
    $request->setUserResolver(static fn (): User => $user);
    $request->setLaravelSession(app('session')->driver());

    return $request;
}

/** @param array<string, mixed> $input */
function pgAuthorizationWorker(int $id, array $input): Process
{
    $worker = new Process([PHP_BINARY, __DIR__.'/Fixtures/credential-authorization-worker.php']);
    $worker->setInput(json_encode(['worker' => $id, ...$input], JSON_THROW_ON_ERROR));
    $worker->start();

    return $worker;
}

/** @param list<Process> $workers */
function pgWaitForAuthorizationLocks(array $workers): void
{
    $deadline = microtime(true) + 30;

    while (microtime(true) < $deadline) {
        foreach ($workers as $worker) {
            if (! $worker->isRunning()) {
                throw new RuntimeException('Authorization worker exited before the lock barrier: '.$worker->getOutput().$worker->getErrorOutput());
            }
        }

        $blocked = (int) DB::connection('pgsql_testing_probe')->scalar(<<<'SQL'
            select count(*) from pg_stat_activity
            where datname = current_database()
              and application_name like 'bfc-credential-authorization-worker-%'
              and state = 'active'
              and wait_event_type = 'Lock'
              and query like '%credential_authorizations%'
            SQL);

        if ($blocked === count($workers)) {
            return;
        }

        usleep(2000);
    }

    throw new RuntimeException('Authorization workers did not reach the row-lock barrier.');
}

function pgWaitForAuthorizationWorkerLock(Process $worker, int $id, string $queryFragment): void
{
    $deadline = microtime(true) + 30;

    while (microtime(true) < $deadline) {
        if (! $worker->isRunning()) {
            throw new RuntimeException('Authorization worker exited before its staged lock: '.$worker->getOutput().$worker->getErrorOutput());
        }

        $blocked = (int) DB::connection('pgsql_testing_probe')->scalar(<<<'SQL'
            select count(*) from pg_stat_activity
            where datname = current_database()
              and application_name = ?
              and state = 'active'
              and wait_event_type = 'Lock'
              and query like ?
            SQL, ['bfc-credential-authorization-worker-'.$id, '%'.$queryFragment.'%']);

        if ($blocked === 1) {
            return;
        }

        usleep(2000);
    }

    throw new RuntimeException('Authorization worker did not reach its staged lock.');
}

/** @param list<Process> $workers @return list<array<string, mixed>> */
function pgFinishAuthorizationWorkers(array $workers): array
{
    return array_map(static function (Process $worker): array {
        $worker->wait();
        expect($worker->isSuccessful())->toBeTrue($worker->getOutput().$worker->getErrorOutput());

        return json_decode($worker->getOutput(), true, flags: JSON_THROW_ON_ERROR);
    }, $workers);
}

beforeEach(function (): void {
    DeviceFlowDeclaration::$profiles = [];
    DeviceFlowDeclaration::$authorizeCalls = 0;
    DeviceFlowDeclaration::$resolvedSubject = null;
    DeviceFlowDeclaration::$selfServiceAbilities = [];
    DeviceFlowDeclaration::$selfServiceKinds = [CredentialKind::Bearer];
    config([
        'built-for-cloud.credentials.declaration' => DeviceFlowDeclaration::class,
        'built-for-cloud.credentials.app_purposes' => ['test.device' => CredentialPurpose::Consumption->value, 'test.loopback' => CredentialPurpose::Consumption->value],
        'built-for-cloud.ui.credential_purposes' => ['test.device', 'test.loopback'],
    ]);
});

it('serializes device and loopback exchange to one credential and one event set', function (string $flow): void {
    $user = User::query()->create(['name' => 'Postgres authorization', 'email' => $flow.'-authorization@example.test']);
    $purpose = $flow === 'device' ? 'test.device' : 'test.loopback';
    $profile = pgAuthorizationProfile($user, $purpose);
    $request = pgAuthorizationRequest($this, $user, $profile);
    $verifier = str_repeat('v', 43);
    $redirect = 'http://127.0.0.1:49152/callback';

    if ($flow === 'device') {
        $start = app(StartDeviceAuthorization::class)($request, $purpose);
        $code = $start->deviceCode->reveal();
        app(DecideDeviceAuthorization::class)($request, $start->userCode->reveal(), $start->browserNonce->reveal(), true);
    } else {
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        $intent = app(StartLoopbackAuthorization::class)($request, $purpose, $redirect, $challenge, 'S256', str_repeat('s', 32));
        $code = (string) app(DecideLoopbackAuthorization::class)($request, $intent->authorizationId, $intent->browserNonce->reveal(), $intent->state, true)->authorizationCode?->reveal();
    }

    $authorization = DB::table('credential_authorizations')->sole();
    $main = $this->postgresLaneConnection();
    $main->beginTransaction();
    $main->table('credential_authorizations')->where('id', $authorization->id)->lockForUpdate()->sole();
    $input = [...$profile, 'operation' => 'exchange', 'flow' => $flow, 'user_id' => (string) $user->getKey(), 'code' => $code, 'redirect_uri' => $redirect, 'verifier' => $verifier];
    $workers = [pgAuthorizationWorker(1, $input), pgAuthorizationWorker(2, $input)];

    try {
        pgWaitForAuthorizationLocks($workers);
        $main->commit();
        $outcomes = array_count_values(array_column(pgFinishAuthorizationWorkers($workers), 'outcome'));
        ksort($outcomes);

        expect($outcomes)->toBe(['invalid_grant' => 1, 'success' => 1])
            ->and(Credential::query()->count())->toBe(1)
            ->and(DB::table('credential_authorizations')->sole()->status)->toBe('consumed')
            ->and(CredentialAuditEvent::query()->where('credential_authorization_id', $authorization->id)->whereIn('event', [LifecycleEventType::Issued->value, LifecycleEventType::Exchanged->value])->count())->toBe(2);
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
})->with(['device', 'loopback']);

it('enforces production shape constraints and records every authorization event name', function (): void {
    $user = User::query()->create(['name' => 'Postgres constraints', 'email' => 'postgres-constraints@example.test']);
    $profile = pgAuthorizationProfile($user, 'test.device');
    $request = pgAuthorizationRequest($this, $user, $profile);
    $approved = app(StartDeviceAuthorization::class)($request, 'test.device');
    app(DecideDeviceAuthorization::class)($request, $approved->userCode->reveal(), $approved->browserNonce->reveal(), true);
    $denied = app(StartDeviceAuthorization::class)($request, 'test.device');
    app(DecideDeviceAuthorization::class)($request, $denied->userCode->reveal(), $denied->browserNonce->reveal(), false);

    expect(CredentialAuditEvent::query()->whereIn('event', [
        LifecycleEventType::CredentialAuthorizationStarted->value,
        LifecycleEventType::CredentialAuthorizationApproved->value,
        LifecycleEventType::CredentialAuthorizationDenied->value,
    ])->distinct()->count('event'))->toBe(3)
        ->and(fn () => DB::table('credential_authorizations')->where('status', 'approved')->update(['denial_reason' => 'user_denied']))
        ->toThrow(QueryException::class);
});

it('serializes concurrent cadence updates on the authorization row', function (): void {
    $user = User::query()->create(['name' => 'Postgres cadence', 'email' => 'postgres-cadence@example.test']);
    $profile = pgAuthorizationProfile($user, 'test.device');
    $request = pgAuthorizationRequest($this, $user, $profile);
    $start = app(StartDeviceAuthorization::class)($request, 'test.device');
    $authorization = DB::table('credential_authorizations')->sole();
    $main = $this->postgresLaneConnection();
    $main->beginTransaction();
    $main->table('credential_authorizations')->where('id', $authorization->id)->lockForUpdate()->sole();
    $input = [...$profile, 'operation' => 'exchange', 'flow' => 'device', 'user_id' => (string) $user->getKey(), 'code' => $start->deviceCode->reveal(), 'redirect_uri' => '', 'verifier' => ''];
    $workers = [pgAuthorizationWorker(3, $input), pgAuthorizationWorker(4, $input)];

    try {
        pgWaitForAuthorizationLocks($workers);
        $main->commit();
        $outcomes = array_column(pgFinishAuthorizationWorkers($workers), 'outcome');
        sort($outcomes);
        expect($outcomes)->toBe(['authorization_pending', 'slow_down'])
            ->and(DB::table('credential_authorizations')->sole()->effective_interval)->toBe(10);
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

it('serializes concurrent browser decisions with the same bound submission nonce', function (): void {
    $user = User::query()->create(['name' => 'Postgres decision', 'email' => 'postgres-decision@example.test']);
    $profile = pgAuthorizationProfile($user, 'test.device');
    $request = pgAuthorizationRequest($this, $user, $profile);
    $start = app(StartDeviceAuthorization::class)($request, 'test.device');
    $authorization = DB::table('credential_authorizations')->sole();
    $userCode = $start->userCode->reveal();
    $browserNonce = $start->browserNonce->reveal();
    $sessionId = $request->session()->getId();
    $submissionNonce = SubmissionNonce::issue(
        $sessionId,
        (string) $user->getKey(),
        CredentialVerb::Issue,
        'device-authorization:'.$authorization->id.':approve',
    );
    $main = $this->postgresLaneConnection();
    $main->beginTransaction();
    $main->table('credential_authorizations')->where('id', $authorization->id)->lockForUpdate()->sole();
    $input = [
        ...$profile,
        'operation' => 'decision',
        'user_id' => (string) $user->getKey(),
        'authorization_id' => (string) $authorization->id,
        'user_code' => $userCode,
        'browser_nonce' => $browserNonce,
        'session_id' => $sessionId,
        'submission_nonce' => $submissionNonce,
    ];
    $workers = [pgAuthorizationWorker(7, $input), pgAuthorizationWorker(8, $input)];

    try {
        pgWaitForAuthorizationLocks($workers);
        $main->commit();
        $outcomes = array_count_values(array_column(pgFinishAuthorizationWorkers($workers), 'outcome'));
        ksort($outcomes);

        expect($outcomes)->toBe(['approved' => 1, 'authorization_unavailable' => 1])
            ->and(DB::table('credential_authorizations')->sole()->status)->toBe('approved')
            ->and(CredentialAuditEvent::query()
                ->where('credential_authorization_id', $authorization->id)
                ->where('event', LifecycleEventType::CredentialAuthorizationApproved->value)
                ->count())->toBe(1)
            ->and(Credential::query()->count())->toBe(0)
            ->and(DB::table('bfc_submission_nonces')->where('nonce_hash', hash('sha256', $submissionNonce))->exists())->toBeFalse();
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

it('contains exchange races through direct offboarding and real managed denial', function (string $containment): void {
    $user = User::query()->create(['name' => 'Postgres containment', 'email' => $containment.'-containment@example.test']);
    $profile = pgAuthorizationProfile($user, 'test.device');
    $request = pgAuthorizationRequest($this, $user, $profile);
    $start = app(StartDeviceAuthorization::class)($request, 'test.device');
    app(DecideDeviceAuthorization::class)($request, $start->userCode->reveal(), $start->browserNonce->reveal(), true);
    $authorization = DB::table('credential_authorizations')->sole();

    if ($containment === 'managed') {
        DB::table('bfc_authority')->updateOrInsert(
            ['key' => InstallationAuthority::KEY],
            [
                'mode' => AuthorityMode::Managed->value,
                'generation' => 7,
                'issuer' => 'https://issuer.example.test',
                'connection_id' => 'connection-fixture',
                'organization_id' => 'organization-fixture',
                'installation_id' => 'postgres-installation',
                'authority_base_url' => 'https://authority.example.test',
                'managed_connection_status' => 'active',
                'created_at' => now(),
                'updated_at' => now(),
            ],
        );
        config(['built-for-cloud.managed.client_secret' => 'fixture-secret']);
        $user->forceFill([
            'scalpels_issuer' => 'https://issuer.example.test',
            'scalpels_connection_id' => 'connection-fixture',
            'scalpels_id' => 'postgres-managed-user',
            'membership_confirmed_at' => now(),
            'membership_response_at' => now(),
            'managed_membership_status' => 'active',
            'managed_membership_generation' => 7,
            'managed_membership_roster_version' => 1,
            'managed_membership_response_sequence' => 1,
        ])->save();
    }

    $main = $this->postgresLaneConnection();
    $main->beginTransaction();
    $main->statement('LOCK TABLE credentials IN ACCESS EXCLUSIVE MODE');
    $exchange = pgAuthorizationWorker(5, [...$profile, 'operation' => 'exchange', 'flow' => 'device', 'user_id' => (string) $user->getKey(), 'code' => $start->deviceCode->reveal(), 'redirect_uri' => '', 'verifier' => '']);
    pgWaitForAuthorizationWorkerLock($exchange, 5, 'credentials');
    $contain = pgAuthorizationWorker(6, [...$profile, 'operation' => $containment === 'managed' ? 'managed_denial' : 'offboard', 'user_id' => (string) $user->getKey(), 'now' => now()->toAtomString()]);
    $workers = [$exchange, $contain];

    try {
        pgWaitForAuthorizationWorkerLock($contain, 6, 'credential_authorizations');
        $main->commit();
        $outcomes = pgFinishAuthorizationWorkers($workers);
        expect($outcomes[0]['outcome'])->toBe('success')
            ->and($outcomes[1]['outcome'])->toBeIn(['offboarded', 'denied']);
        expect(Credential::query()->whereNull('revoked_at')->count())->toBe(0)
            ->and(DB::table('credential_authorizations')->sole()->status)->toBe('consumed');
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
})->with(['direct', 'managed']);
