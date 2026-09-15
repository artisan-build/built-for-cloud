<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\DecideDeviceAuthorization;
use ArtisanBuild\BuiltForCloud\Actions\DecideLoopbackAuthorization;
use ArtisanBuild\BuiltForCloud\Actions\ExchangeLoopbackAuthorization;
use ArtisanBuild\BuiltForCloud\Actions\PollDeviceAuthorization;
use ArtisanBuild\BuiltForCloud\Actions\StartDeviceAuthorization;
use ArtisanBuild\BuiltForCloud\Actions\StartLoopbackAuthorization;
use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\Auth\CredentialResolver;
use ArtisanBuild\BuiltForCloud\BoundBearerCredentialAuthenticator;
use ArtisanBuild\BuiltForCloud\BoundCredentialScope;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAlgorithm;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationOwnership;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationPolicy;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationAuthority;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationProfile;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialMaterialRole;
use ArtisanBuild\BuiltForCloud\CredentialProtocolBinding;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialAuthorizationRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\StandaloneAccess;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\DeviceFlowDeclaration;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Database\QueryException;
use Illuminate\Http\Request;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    DeviceFlowDeclaration::$profiles = [];
    DeviceFlowDeclaration::$authorizeCalls = 0;
    config([
        'built-for-cloud.credentials.declaration' => DeviceFlowDeclaration::class,
        'built-for-cloud.credentials.app_purposes' => [
            'test.device' => CredentialPurpose::Consumption->value,
            'test.loopback' => CredentialPurpose::Consumption->value,
        ],
        'built-for-cloud.ui.credential_purposes' => ['test.device', 'test.loopback'],
        'built-for-cloud.ui.personal_credentials' => false,
        'built-for-cloud.ui.installation_credentials' => false,
    ]);
});

function deviceFlowUser(): User
{
    return User::query()->create([
        'name' => 'Device flow operator',
        'email' => 'device-flow@example.test',
        'password' => bcrypt('test-created-password'),
    ]);
}

function deviceProfile(User $user, string $purpose = 'test.device'): CredentialAuthorizationProfile
{
    return new CredentialAuthorizationProfile(
        $purpose,
        new BoundCredentialScope(
            $purpose,
            new Subject(SubjectType::UserPrincipal, 'device-user:'.$user->getKey()),
            'installation-test-1',
            'application-test-1',
            'https://device-audience.example.test',
        ),
        CredentialAuthorizationOwnership::Personal,
        [],
        now()->addDay(),
        600,
        5,
    );
}

function deviceRequest(object $test, User $user): Request
{
    $test->actingAsVersioned($user, 'web');
    $request = request();
    $request->setUserResolver(static fn (): User => $user);
    $request->setLaravelSession(app('session')->driver());

    return $request;
}

it('runs one hash-only device lifecycle and authenticates only the exact bound bearer', function (): void {
    Carbon::setTestNow('2026-09-15 12:00:00');
    $user = deviceFlowUser();
    DeviceFlowDeclaration::$profiles = [deviceProfile($user)];
    $request = deviceRequest($this, $user);
    $start = app(StartDeviceAuthorization::class)($request, 'test.device', '  Test-created device  ');
    $deviceCode = $start->deviceCode->reveal();
    $userCode = $start->userCode->reveal();
    $row = DB::table('credential_authorizations')->sole();

    expect($deviceCode)->toMatch('/^[A-Za-z0-9_-]{43}$/')
        ->and($userCode)->toMatch('/^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/')
        ->and($row->device_code_hash)->toBe(hash('sha256', $deviceCode))
        ->and($row->user_code_hash)->toBe(hash('sha256', $userCode))
        ->and($row->label)->toBe('Test-created device')
        ->and(json_encode((array) $row))->not->toContain($deviceCode, $userCode);

    expect(fn () => app(PollDeviceAuthorization::class)($request, $deviceCode))
        ->toThrow(CredentialAuthorizationRefused::class, 'authorization_pending');
    app(DecideDeviceAuthorization::class)($request, strtolower(str_replace('-', '', $userCode)), true);
    $this->travel(5)->seconds();
    $token = app(PollDeviceAuthorization::class)($request, $deviceCode);
    $plaintext = $token->accessToken->reveal();
    $credential = Credential::query()->findOrFail($token->credentialId);
    $binding = CredentialProtocolBinding::query()->whereKey($credential->id)->sole();

    expect($credential->secret_hash)->toBe(hash('sha256', $plaintext))
        ->and($credential->user_id)->toBe((string) $user->getKey())
        ->and($binding->algorithm)->toBe(CredentialAlgorithm::Bearer)
        ->and($binding->material_role)->toBe(CredentialMaterialRole::Originator)
        ->and($binding->exactlyMatches(
            $credential,
            DeviceFlowDeclaration::$profiles[0]->scope,
            CredentialPurpose::Consumption,
            CredentialAlgorithm::Bearer,
            CredentialMaterialRole::Originator,
        ))->toBeTrue()
        ->and(CredentialAuditEvent::query()->pluck('event')->sort()->values()->all())->toBe(collect([
            LifecycleEventType::CredentialAuthorizationStarted,
            LifecycleEventType::CredentialAuthorizationApproved,
            LifecycleEventType::Issued,
            LifecycleEventType::Exchanged,
        ])->sort()->values()->all());

    $use = Request::create('/protected', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$plaintext]);
    $bound = app(BoundBearerCredentialAuthenticator::class)->authenticate($use, 'test.device');
    expect($bound?->id)->toBe($credential->id)
        ->and(app(CredentialResolver::class)->resolve(CredentialKind::Bearer, $plaintext))->toBeNull();

    DeviceFlowDeclaration::$authorizeCalls = 0;
    DeviceFlowDeclaration::$profiles = [new CredentialAuthorizationProfile(
        'test.device',
        new BoundCredentialScope('test.device', DeviceFlowDeclaration::$profiles[0]->scope->subject, 'wrong-installation', 'application-test-1', 'https://device-audience.example.test'),
        CredentialAuthorizationOwnership::Personal,
        [],
        now()->addDay(),
        600,
        5,
    )];
    $wrong = Request::create('/protected', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$plaintext]);
    expect(app(BoundBearerCredentialAuthenticator::class)->authenticate($wrong, 'test.device'))->toBeNull()
        ->and(DeviceFlowDeclaration::$authorizeCalls)->toBe(0);
});

it('uses the same mint and exact binding for loopback with PKCE and byte-exact redirect', function (): void {
    $user = deviceFlowUser();
    DeviceFlowDeclaration::$profiles = [deviceProfile($user, 'test.loopback')];
    $request = deviceRequest($this, $user);
    $verifier = str_repeat('v', 43);
    $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    $redirect = 'http://127.0.0.1:49152/callback?test=created';
    $intent = app(StartLoopbackAuthorization::class)(
        $request,
        'test.loopback',
        $redirect,
        $challenge,
        'S256',
        str_repeat('s', 32),
        'Loopback test',
    );
    $decision = app(DecideLoopbackAuthorization::class)($request, $intent->authorizationId, true);
    $code = $decision->authorizationCode?->reveal();
    $token = app(ExchangeLoopbackAuthorization::class)($request, (string) $code, $redirect, $verifier);

    expect($token->appPurpose)->toBe('test.loopback')
        ->and(Credential::query()->count())->toBe(1)
        ->and(CredentialProtocolBinding::query()->count())->toBe(1)
        ->and(DB::table('credential_authorizations')->sole()->status)->toBe('consumed');

    expect(fn () => app(ExchangeLoopbackAuthorization::class)($request, (string) $code, $redirect, $verifier))
        ->toThrow(CredentialAuthorizationRefused::class, 'invalid_grant');
    expect(fn () => app(ExchangeLoopbackAuthorization::class)($request, str_repeat('a', 43), $redirect.'x', $verifier))
        ->toThrow(CredentialAuthorizationRefused::class);
});

it('refuses missing duplicate and installation operator profiles before writing', function (): void {
    $user = deviceFlowUser();
    $request = deviceRequest($this, $user);

    expect(fn () => app(StartDeviceAuthorization::class)($request, 'test.device'))
        ->toThrow(InvalidCredentialInput::class);
    DeviceFlowDeclaration::$profiles = [deviceProfile($user), deviceProfile($user)];
    expect(fn () => app(StartDeviceAuthorization::class)($request, 'test.device'))
        ->toThrow(InvalidCredentialInput::class);
    DeviceFlowDeclaration::$profiles = [new CredentialAuthorizationProfile(
        'test.device',
        new BoundCredentialScope('test.device', new Subject(SubjectType::Installation, 'install-1'), 'install-1', 'app-1', 'https://audience.example.test'),
        CredentialAuthorizationOwnership::Installation,
        ['mcp:read'],
        null,
        60,
        5,
    )];
    expect(fn () => app(StartDeviceAuthorization::class)($request, 'test.device'))
        ->toThrow(InvalidCredentialInput::class)
        ->and(DB::table('credential_authorizations')->count())->toBe(0)
        ->and(CredentialAuditEvent::query()->count())->toBe(0);
});

it('serializes cadence and contains personal grants before revocation without following installation creators', function (): void {
    Carbon::setTestNow('2026-09-15 12:00:00');
    $user = deviceFlowUser();
    $personal = deviceProfile($user);
    DeviceFlowDeclaration::$profiles = [$personal];
    $request = deviceRequest($this, $user);
    $personalStart = app(StartDeviceAuthorization::class)($request, 'test.device');
    $personalCode = $personalStart->deviceCode->reveal();

    expect(fn () => app(PollDeviceAuthorization::class)($request, $personalCode))
        ->toThrow(CredentialAuthorizationRefused::class, 'authorization_pending');
    expect(fn () => app(PollDeviceAuthorization::class)($request, $personalCode))
        ->toThrow(CredentialAuthorizationRefused::class, 'slow_down');
    expect(DB::table('credential_authorizations')->where('device_code_hash', hash('sha256', $personalCode))->value('effective_interval'))
        ->toBe(10);

    $installation = new CredentialAuthorizationProfile(
        'test.device',
        new BoundCredentialScope('test.device', new Subject(SubjectType::Installation, 'install-1'), 'install-1', 'app-1', 'https://audience.example.test'),
        CredentialAuthorizationOwnership::Installation,
        [],
        null,
        60,
        5,
    );
    DeviceFlowDeclaration::$profiles = [$installation];
    $installationStart = app(StartDeviceAuthorization::class)($request, 'test.device');
    $installationCode = $installationStart->deviceCode->reveal();
    $installationUserCode = $installationStart->userCode->reveal();
    app(DecideDeviceAuthorization::class)($request, $installationUserCode, true);
    $installationToken = app(PollDeviceAuthorization::class)($request, $installationCode);
    $installationCredential = Credential::query()->findOrFail($installationToken->credentialId);

    DB::transaction(static fn () => StandaloneAccess::invalidateAccountBoundState($user));

    expect(DB::table('credential_authorizations')->where('device_code_hash', hash('sha256', $personalCode))->value('status'))
        ->toBe('denied')
        ->and($installationCredential->refresh()->revoked_at)->toBeNull()
        ->and($installationCredential->user_id)->toBeNull();
});

it('refuses malformed profile authority and exact package-boundary values before writing', function (callable $mutate): void {
    $user = deviceFlowUser();
    $request = deviceRequest($this, $user);
    DeviceFlowDeclaration::$profiles = [deviceProfile($user)];
    $mutate($user);

    expect(fn () => app(StartDeviceAuthorization::class)($request, 'test.device', 'test-created'))
        ->toThrow(InvalidCredentialInput::class)
        ->and(DB::table('credential_authorizations')->count())->toBe(0)
        ->and(CredentialAuditEvent::query()->count())->toBe(0);
})->with([
    'missing mapping' => fn () => config(['built-for-cloud.credentials.app_purposes' => []]),
    'list-valued mapping' => fn () => config(['built-for-cloud.credentials.app_purposes' => ['test.device' => [CredentialPurpose::Consumption->value], 'test.loopback' => CredentialPurpose::Consumption->value]]),
    'unknown mapping' => fn () => config(['built-for-cloud.credentials.app_purposes' => ['test.device' => 'unknown-purpose', 'test.loopback' => CredentialPurpose::Consumption->value]]),
    'duplicate UI authority' => fn () => config(['built-for-cloud.ui.credential_purposes' => ['test.device', 'test.device']]),
    'malformed profile list' => fn () => DeviceFlowDeclaration::$profiles = [new stdClass],
    'ttl below minimum' => fn (User $user) => DeviceFlowDeclaration::$profiles = [new CredentialAuthorizationProfile('test.device', deviceProfile($user)->scope, CredentialAuthorizationOwnership::Personal, [], null, 59, 5)],
    'ttl above maximum' => fn (User $user) => DeviceFlowDeclaration::$profiles = [new CredentialAuthorizationProfile('test.device', deviceProfile($user)->scope, CredentialAuthorizationOwnership::Personal, [], null, 901, 5)],
    'cadence below minimum' => fn (User $user) => DeviceFlowDeclaration::$profiles = [new CredentialAuthorizationProfile('test.device', deviceProfile($user)->scope, CredentialAuthorizationOwnership::Personal, [], null, 60, 4)],
    'cadence above maximum' => fn (User $user) => DeviceFlowDeclaration::$profiles = [new CredentialAuthorizationProfile('test.device', deviceProfile($user)->scope, CredentialAuthorizationOwnership::Personal, [], null, 60, 31)],
]);

it('rejects every exact-bound drift before declaration or usage effects', function (callable $drift): void {
    Carbon::setTestNow('2026-09-15 12:00:00');
    $user = deviceFlowUser();
    DeviceFlowDeclaration::$profiles = [deviceProfile($user)];
    $request = deviceRequest($this, $user);
    $start = app(StartDeviceAuthorization::class)($request, 'test.device');
    app(DecideDeviceAuthorization::class)($request, $start->userCode->reveal(), true);
    $token = app(PollDeviceAuthorization::class)($request, $start->deviceCode->reveal());
    $secret = $token->accessToken->reveal();
    $credential = Credential::query()->findOrFail($token->credentialId);
    $drift($credential, $user);
    DeviceFlowDeclaration::$authorizeCalls = 0;

    $use = Request::create('/protected', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$secret]);
    try {
        $resolved = app(BoundBearerCredentialAuthenticator::class)->authenticate($use, 'test.device');
    } catch (InvalidCredentialInput) {
        $resolved = null;
    }

    expect($resolved)->toBeNull()
        ->and(DeviceFlowDeclaration::$authorizeCalls)->toBe(0)
        ->and($credential->refresh()->last_used_at)->toBeNull();
})->with([
    'protocol purpose' => fn (Credential $credential) => DB::table('credentials')->where('id', $credential->id)->update(['purpose' => CredentialPurpose::Mcp->value]),
    'subject' => fn (Credential $credential) => DB::table('credentials')->where('id', $credential->id)->update(['subject_ref' => 'wrong-subject']),
    'installation' => fn (Credential $credential) => DB::table('credential_protocol_bindings')->where('credential_id', $credential->id)->update(['installation_ref' => 'wrong-installation']),
    'application' => fn (Credential $credential) => DB::table('credential_protocol_bindings')->where('credential_id', $credential->id)->update(['application_ref' => 'wrong-application']),
    'audience' => fn (Credential $credential) => DB::table('credential_protocol_bindings')->where('credential_id', $credential->id)->update(['audience' => 'wrong-audience']),
    'algorithm' => fn (Credential $credential) => DB::table('credential_protocol_bindings')->where('credential_id', $credential->id)->update(['algorithm' => CredentialAlgorithm::Rs256->value]),
    'material role' => fn (Credential $credential) => DB::table('credential_protocol_bindings')->where('credential_id', $credential->id)->update(['material_role' => CredentialMaterialRole::VerificationCopy->value]),
    'scope hash' => fn (Credential $credential) => DB::table('credential_protocol_bindings')->where('credential_id', $credential->id)->update(['scope_hash' => str_repeat('0', 64)]),
    'ownership' => function (Credential $credential, User $user): void {
        DeviceFlowDeclaration::$profiles = [new CredentialAuthorizationProfile('test.device', deviceProfile($user)->scope, CredentialAuthorizationOwnership::Installation, [], now()->addDay(), 600, 5)];
    },
    'abilities' => function (Credential $credential, User $user): void {
        DeviceFlowDeclaration::$profiles = [new CredentialAuthorizationProfile('test.device', deviceProfile($user)->scope, CredentialAuthorizationOwnership::Personal, ['mcp:read'], now()->addDay(), 600, 5)];
    },
    'expiry' => function (Credential $credential, User $user): void {
        DeviceFlowDeclaration::$profiles = [new CredentialAuthorizationProfile('test.device', deviceProfile($user)->scope, CredentialAuthorizationOwnership::Personal, [], now()->addDays(2), 600, 5)];
    },
]);

it('rolls back a credential collision and permits one later exchange without redelivery', function (): void {
    Carbon::setTestNow('2026-09-15 12:00:00');
    $user = deviceFlowUser();
    DeviceFlowDeclaration::$profiles = [deviceProfile($user)];
    $request = deviceRequest($this, $user);
    $start = app(StartDeviceAuthorization::class)($request, 'test.device');
    $code = $start->deviceCode->reveal();
    app(DecideDeviceAuthorization::class)($request, $start->userCode->reveal(), true);
    $collision = (string) Str::uuid();
    Credential::query()->create([
        'id' => $collision,
        'kind' => CredentialKind::Bearer,
        'purpose' => CredentialPurpose::Consumption,
        'subject_type' => SubjectType::UserPrincipal,
        'subject_ref' => 'collision-subject',
        'secret_hash' => hash('sha256', 'collision-secret'),
    ]);
    Str::createUuidsUsing(static fn () => Ramsey\Uuid\Uuid::fromString($collision));

    try {
        expect(fn () => app(PollDeviceAuthorization::class)($request, $code))->toThrow(QueryException::class);
    } finally {
        Str::createUuidsNormally();
    }

    expect(DB::table('credential_authorizations')->sole()->status)->toBe('approved')
        ->and(Credential::query()->count())->toBe(1)
        ->and(CredentialAuditEvent::query()->where('event', LifecycleEventType::Issued)->count())->toBe(0);

    $lostResponse = app(PollDeviceAuthorization::class)($request, $code);
    expect(Credential::query()->whereKey($lostResponse->credentialId)->exists())->toBeTrue()
        ->and(fn () => app(PollDeviceAuthorization::class)($request, $code))
        ->toThrow(CredentialAuthorizationRefused::class, 'invalid_grant');
});

it('uses five-minute freshness and thirty-minute grace without turning faults into denial', function (): void {
    Carbon::setTestNow('2026-09-15 12:00:00');
    DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
        'mode' => AuthorityMode::Managed->value,
        'generation' => 7,
        'issuer' => 'https://issuer.example.test',
        'connection_id' => 'connection-fixture',
        'organization_id' => 'organization-fixture',
        'installation_id' => 'installation-fixture',
        'authority_base_url' => 'https://authority.example.test',
        'managed_connection_status' => 'active',
    ]);
    config(['built-for-cloud.managed.client_secret' => 'fixture-client-secret']);
    Http::fake(static fn (ClientRequest $request) => Http::response(['error' => 'test-created-outage'], 503));
    $user = deviceFlowUser();
    $user->forceFill([
        'role' => 'member',
        'status' => 'active',
        'scalpels_issuer' => 'https://issuer.example.test',
        'scalpels_connection_id' => 'connection-fixture',
        'scalpels_id' => 'managed-device-user',
        'membership_confirmed_at' => now(),
        'membership_checked_at' => now(),
        'membership_response_at' => now(),
        'managed_membership_status' => 'active',
        'managed_membership_role' => 'member',
        'managed_membership_generation' => 7,
        'managed_membership_roster_version' => 1,
        'managed_membership_response_sequence' => 1,
        'managed_membership_responded_at' => now(),
    ])->save();
    $profile = deviceProfile($user);
    $request = deviceRequest($this, $user);

    Carbon::setTestNow('2026-09-15 12:04:59');
    expect(app(CredentialAuthorizationPolicy::class)->authority($profile, $request, (string) $user->getKey()))->toBe(CredentialAuthorizationAuthority::Allowed);
    Carbon::setTestNow('2026-09-15 12:05:00');
    expect(app(CredentialAuthorizationPolicy::class)->authority($profile, $request, (string) $user->getKey()))->toBe(CredentialAuthorizationAuthority::Allowed);
    Cache::flush();
    $user->forceFill(['status' => 'inactive', 'managed_membership_status' => 'removed'])->save();
    $installation = new CredentialAuthorizationProfile(
        'test.device',
        new BoundCredentialScope('test.device', new Subject(SubjectType::Installation, 'installation-fixture'), 'installation-fixture', 'application-fixture', 'audience.example.test'),
        CredentialAuthorizationOwnership::Installation,
        [],
        null,
        600,
        5,
    );
    Carbon::setTestNow('2026-09-15 12:29:59');
    expect(app(CredentialAuthorizationPolicy::class)->authority($installation, $request, (string) $user->getKey(), true))->toBe(CredentialAuthorizationAuthority::Allowed);
    Cache::flush();
    Carbon::setTestNow('2026-09-15 12:30:00');
    expect(app(CredentialAuthorizationPolicy::class)->authority($installation, $request, (string) $user->getKey(), true))->toBe(CredentialAuthorizationAuthority::Unavailable)
        ->and($user->refresh()->status)->toBe('inactive')
        ->and(CredentialAuditEvent::query()->count())->toBe(0);
});

it('honours inclusive lifetime and cadence bounds and gives expiry priority over cadence', function (int $ttl, int $interval): void {
    Carbon::setTestNow('2026-09-15 12:00:00');
    $user = deviceFlowUser();
    $base = deviceProfile($user);
    DeviceFlowDeclaration::$profiles = [new CredentialAuthorizationProfile(
        'test.device',
        $base->scope,
        CredentialAuthorizationOwnership::Personal,
        [],
        null,
        $ttl,
        $interval,
    )];
    $request = deviceRequest($this, $user);
    $start = app(StartDeviceAuthorization::class)($request, 'test.device');
    $code = $start->deviceCode->reveal();

    expect($start->expiresIn)->toBe($ttl)
        ->and($start->interval)->toBe($interval)
        ->and(fn () => app(PollDeviceAuthorization::class)($request, $code))
        ->toThrow(CredentialAuthorizationRefused::class, 'authorization_pending');
    Carbon::setTestNow(Carbon::parse('2026-09-15 12:00:00')->addSeconds($ttl));
    expect(fn () => app(PollDeviceAuthorization::class)($request, $code))
        ->toThrow(CredentialAuthorizationRefused::class, 'expired_token')
        ->and(DB::table('credential_authorizations')->sole()->status)->toBe('pending');
})->with([
    'minimums' => [60, 5],
    'maximums' => [900, 30],
]);

it('turns profile drift into one terminal denial without minting', function (): void {
    Carbon::setTestNow('2026-09-15 12:00:00');
    $user = deviceFlowUser();
    DeviceFlowDeclaration::$profiles = [deviceProfile($user)];
    $request = deviceRequest($this, $user);
    $start = app(StartDeviceAuthorization::class)($request, 'test.device');
    app(DecideDeviceAuthorization::class)($request, $start->userCode->reveal(), true);
    DeviceFlowDeclaration::$profiles = [new CredentialAuthorizationProfile(
        'test.device',
        new BoundCredentialScope('test.device', deviceProfile($user)->scope->subject, 'installation-test-1', 'application-test-1', 'drifted-audience.example.test'),
        CredentialAuthorizationOwnership::Personal,
        [],
        now()->addDay(),
        600,
        5,
    )];

    expect(fn () => app(PollDeviceAuthorization::class)($request, $start->deviceCode->reveal()))
        ->toThrow(CredentialAuthorizationRefused::class, 'access_denied')
        ->and(DB::table('credential_authorizations')->sole()->status)->toBe('denied')
        ->and(Credential::query()->count())->toBe(0)
        ->and(CredentialAuditEvent::query()->where('event', LifecycleEventType::CredentialAuthorizationDenied)->count())->toBe(1);
});

it('rejects malformed opaque proofs before touching grant cadence or audit', function (string $code): void {
    $user = deviceFlowUser();
    DeviceFlowDeclaration::$profiles = [deviceProfile($user)];
    $request = deviceRequest($this, $user);
    app(StartDeviceAuthorization::class)($request, 'test.device');
    $before = (array) DB::table('credential_authorizations')->sole();
    $events = CredentialAuditEvent::query()->count();

    expect(fn () => app(PollDeviceAuthorization::class)($request, $code))
        ->toThrow(CredentialAuthorizationRefused::class, 'invalid_request')
        ->and((array) DB::table('credential_authorizations')->sole())->toBe($before)
        ->and(CredentialAuditEvent::query()->count())->toBe($events);
})->with([
    'empty' => '',
    'short' => str_repeat('a', 42),
    'long' => str_repeat('a', 44),
    'padding' => str_repeat('a', 42).'=',
    'non-ascii' => str_repeat('a', 42).'é',
]);
