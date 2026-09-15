<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\DecideDeviceAuthorization;
use ArtisanBuild\BuiltForCloud\Actions\DecideLoopbackAuthorization;
use ArtisanBuild\BuiltForCloud\Actions\ExchangeLoopbackAuthorization;
use ArtisanBuild\BuiltForCloud\Actions\OffboardSubject;
use ArtisanBuild\BuiltForCloud\Actions\PollDeviceAuthorization;
use ArtisanBuild\BuiltForCloud\Actions\StartDeviceAuthorization;
use ArtisanBuild\BuiltForCloud\Actions\StartLoopbackAuthorization;
use ArtisanBuild\BuiltForCloud\Auth\CredentialResolver;
use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\BoundBearerCredentialAuthenticator;
use ArtisanBuild\BuiltForCloud\BoundCredentialScope;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAlgorithm;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationAuthority;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationOwnership;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationPolicy;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationProfile;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialManagementScope;
use ArtisanBuild\BuiltForCloud\CredentialMaterialRole;
use ArtisanBuild\BuiltForCloud\CredentialProtocolBinding;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialAuthorizationRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\ManagedAuthConfirmation;
use ArtisanBuild\BuiltForCloud\ManagedAuthConnection;
use ArtisanBuild\BuiltForCloud\ManagedMembershipResponses;
use ArtisanBuild\BuiltForCloud\OffboardOptions;
use ArtisanBuild\BuiltForCloud\StandaloneAccess;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\DeviceFlowDeclaration;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Ramsey\Uuid\Uuid;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    DeviceFlowDeclaration::$profiles = [];
    DeviceFlowDeclaration::$authorizeCalls = 0;
    DeviceFlowDeclaration::$selfServiceAbilities = [];
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
    app(DecideDeviceAuthorization::class)($request, strtolower(str_replace('-', '', $userCode)), $start->browserNonce->reveal(), true);
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
        ->and(DB::table('credential_audit_events')->orderByRaw('rowid')->pluck('event')->all())->toBe([
            LifecycleEventType::CredentialAuthorizationStarted->value,
            LifecycleEventType::CredentialAuthorizationApproved->value,
            LifecycleEventType::Issued->value,
            LifecycleEventType::Exchanged->value,
        ]);

    $events = DB::table('credential_audit_events')->orderByRaw('rowid')->get();
    expect($events[0]->credential_authorization_id)->toBe($row->id)
        ->and($events[0]->credential_id)->toBeNull()
        ->and($events[0]->code_id)->toBeNull()
        ->and($events[1]->credential_authorization_id)->toBe($row->id)
        ->and($events[1]->credential_id)->toBeNull()
        ->and($events[1]->code_id)->toBeNull()
        ->and($events[2]->credential_authorization_id)->toBe($row->id)
        ->and($events[2]->credential_id)->toBe($credential->id)
        ->and($events[2]->code_id)->toBeNull()
        ->and($events[3]->credential_authorization_id)->toBe($row->id)
        ->and($events[3]->credential_id)->toBe($credential->id)
        ->and($events[3]->code_id)->toBeNull();

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
    $decision = app(DecideLoopbackAuthorization::class)($request, $intent->authorizationId, $intent->browserNonce->reveal(), $intent->state, true);
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

it('checks valid loopback proofs under the lock and preserves approved grants on mismatch', function (string $dimension): void {
    $user = deviceFlowUser();
    DeviceFlowDeclaration::$profiles = [deviceProfile($user, 'test.loopback')];
    $request = deviceRequest($this, $user);
    $verifier = str_repeat('v', 43);
    $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    $redirect = 'http://127.0.0.1:49152/callback?test=created';
    $intent = app(StartLoopbackAuthorization::class)($request, 'test.loopback', $redirect, $challenge, 'S256', str_repeat('s', 32));
    $decision = app(DecideLoopbackAuthorization::class)($request, $intent->authorizationId, $intent->browserNonce->reveal(), $intent->state, true);
    $code = (string) $decision->authorizationCode?->reveal();
    [$attemptedRedirect, $attemptedVerifier] = match ($dimension) {
        'verifier' => [$redirect, str_repeat('w', 43)],
        'path' => ['http://127.0.0.1:49152/other?test=created', $verifier],
        'port' => ['http://127.0.0.1:49153/callback?test=created', $verifier],
    };

    expect(fn () => app(ExchangeLoopbackAuthorization::class)($request, $code, $attemptedRedirect, $attemptedVerifier))
        ->toThrow(CredentialAuthorizationRefused::class, 'invalid_grant')
        ->and(DB::table('credential_authorizations')->where('id', $intent->authorizationId)->value('status'))->toBe('approved')
        ->and(Credential::query()->count())->toBe(0);
})->with(['verifier', 'path', 'port']);

it('returns exact loopback terminal classes without mutating approved proof failures', function (): void {
    Carbon::setTestNow('2026-09-15 12:00:00');
    $user = deviceFlowUser();
    DeviceFlowDeclaration::$profiles = [deviceProfile($user, 'test.loopback')];
    $request = deviceRequest($this, $user);
    $verifier = str_repeat('v', 43);
    $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    $redirect = 'http://127.0.0.1:49152/callback';
    $approve = static function () use ($request, $challenge, $redirect): array {
        $intent = app(StartLoopbackAuthorization::class)($request, 'test.loopback', $redirect, $challenge, 'S256', str_repeat('s', 32));
        $decision = app(DecideLoopbackAuthorization::class)($request, $intent->authorizationId, $intent->browserNonce->reveal(), $intent->state, true);

        return [$intent, (string) $decision->authorizationCode?->reveal()];
    };

    [$expired, $expiredCode] = $approve();
    DB::table('credential_authorizations')->where('id', $expired->authorizationId)->update(['expires_at' => now()]);
    expect(fn () => app(ExchangeLoopbackAuthorization::class)($request, $expiredCode, $redirect, $verifier))
        ->toThrow(CredentialAuthorizationRefused::class, 'expired_token');

    [$denied, $deniedCode] = $approve();
    DB::table('credential_authorizations')->where('id', $denied->authorizationId)->update([
        'status' => 'denied',
        'denial_reason' => 'authority_denied',
    ]);
    expect(fn () => app(ExchangeLoopbackAuthorization::class)($request, $deniedCode, $redirect, $verifier))
        ->toThrow(CredentialAuthorizationRefused::class, 'access_denied');

    [$approved, $approvedCode] = $approve();
    $before = (array) DB::table('credential_authorizations')->where('id', $approved->authorizationId)->sole();
    expect(fn () => app(ExchangeLoopbackAuthorization::class)($request, '', $redirect, $verifier))
        ->toThrow(CredentialAuthorizationRefused::class, 'invalid_request')
        ->and(fn () => app(ExchangeLoopbackAuthorization::class)($request, $approvedCode, 'http://127.0.0.1', $verifier))
        ->toThrow(CredentialAuthorizationRefused::class, 'invalid_request')
        ->and((array) DB::table('credential_authorizations')->where('id', $approved->authorizationId)->sole())->toBe($before);
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

it('enforces the personal self-service ability grant before writing', function (): void {
    $user = deviceFlowUser();
    $request = deviceRequest($this, $user);
    $base = deviceProfile($user);
    DeviceFlowDeclaration::$profiles = [new CredentialAuthorizationProfile(
        'test.device',
        $base->scope,
        CredentialAuthorizationOwnership::Personal,
        ['mcp:read'],
        null,
        60,
        5,
    )];

    expect(fn () => app(StartDeviceAuthorization::class)($request, 'test.device'))
        ->toThrow(InvalidCredentialInput::class)
        ->and(DB::table('credential_authorizations')->count())->toBe(0)
        ->and(CredentialAuditEvent::query()->count())->toBe(0);

    DeviceFlowDeclaration::$selfServiceAbilities = ['mcp:read'];
    $start = app(StartDeviceAuthorization::class)($request, 'test.device');
    expect(DB::table('credential_authorizations')->sole()->abilities)->toBe(json_encode(['mcp:read']))
        ->and($start->deviceCode->revealed())->toBeFalse();
});

it('ignores every UI visibility flag at start exchange and bound use for both transports', function (string $flow, bool $visible): void {
    config([
        'built-for-cloud.ui.credential_purposes' => $visible ? ['test.device', 'test.loopback'] : [],
        'built-for-cloud.ui.personal_credentials' => $visible,
        'built-for-cloud.ui.installation_credentials' => $visible,
    ]);
    $user = deviceFlowUser();
    $purpose = $flow === 'device' ? 'test.device' : 'test.loopback';
    DeviceFlowDeclaration::$profiles = [deviceProfile($user, $purpose)];
    $request = deviceRequest($this, $user);

    if ($flow === 'device') {
        $start = app(StartDeviceAuthorization::class)($request, $purpose);
        app(DecideDeviceAuthorization::class)($request, $start->userCode->reveal(), $start->browserNonce->reveal(), true);
        $token = app(PollDeviceAuthorization::class)($request, $start->deviceCode->reveal());
    } else {
        $verifier = str_repeat('v', 43);
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        $intent = app(StartLoopbackAuthorization::class)($request, $purpose, 'http://127.0.0.1:49152/callback', $challenge, 'S256', str_repeat('s', 32));
        $decision = app(DecideLoopbackAuthorization::class)($request, $intent->authorizationId, $intent->browserNonce->reveal(), $intent->state, true);
        $token = app(ExchangeLoopbackAuthorization::class)($request, (string) $decision->authorizationCode?->reveal(), $intent->redirectUri, $verifier);
    }

    $secret = $token->accessToken->reveal();
    $use = Request::create('/protected', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$secret]);
    expect(app(BoundBearerCredentialAuthenticator::class)->authenticate($use, $purpose)?->id)->toBe($token->credentialId);
})->with([
    'device hidden' => ['device', false],
    'device shown' => ['device', true],
    'loopback hidden' => ['loopback', false],
    'loopback shown' => ['loopback', true],
]);

it('keeps start plaintext out of rows audit outbox and package session serialization', function (): void {
    $user = deviceFlowUser();
    DeviceFlowDeclaration::$profiles = [deviceProfile($user)];
    $request = deviceRequest($this, $user);
    $sessionBefore = serialize($request->session()->all());
    $start = app(StartDeviceAuthorization::class)($request, 'test.device');
    $deviceCode = $start->deviceCode->reveal();
    $userCode = $start->userCode->reveal();
    $nonce = $start->browserNonce->reveal();
    $row = DB::table('credential_authorizations')->sole();
    $persisted = json_encode([
        (array) $row,
        CredentialAuditEvent::query()->get()->toArray(),
        DB::table('credential_outbox')->get()->map(static fn (object $entry): array => (array) $entry)->all(),
    ], JSON_THROW_ON_ERROR);

    expect($row->device_code_hash)->toBe(hash('sha256', $deviceCode))
        ->and($row->user_code_hash)->toBe(hash('sha256', $userCode))
        ->and($row->browser_session_nonce_hash)->toBe(hash('sha256', $nonce))
        ->and($persisted)->not->toContain($deviceCode, $userCode, $nonce)
        ->and(serialize($request->session()->all()))->toBe($sessionBefore);
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
    app(DecideDeviceAuthorization::class)($request, $installationUserCode, $installationStart->browserNonce->reveal(), true);
    $installationToken = app(PollDeviceAuthorization::class)($request, $installationCode);
    $installationCredential = Credential::query()->findOrFail($installationToken->credentialId);

    expect(CredentialManagementScope::memberInstallation()->apply(Credential::query())->whereKey($installationCredential->id)->exists())->toBeTrue();

    DB::transaction(static fn () => StandaloneAccess::invalidateAccountBoundState($user));

    expect(DB::table('credential_authorizations')->where('device_code_hash', hash('sha256', $personalCode))->value('status'))
        ->toBe('denied')
        ->and($installationCredential->refresh()->revoked_at)->toBeNull()
        ->and($installationCredential->user_id)->toBeNull();
});

it('lets an approved installation grant survive real creator denial and exchange', function (): void {
    Carbon::setTestNow('2026-09-15 12:00:00');
    $user = deviceFlowUser();
    $user->forceFill(['role' => 'member'])->save();
    DeviceFlowDeclaration::$profiles = [new CredentialAuthorizationProfile(
        'test.device',
        new BoundCredentialScope('test.device', new Subject(SubjectType::Installation, 'installation-fixture'), 'installation-fixture', 'application-fixture', 'audience.example.test'),
        CredentialAuthorizationOwnership::Installation,
        [],
        null,
        600,
        5,
    )];
    $request = deviceRequest($this, $user);
    $start = app(StartDeviceAuthorization::class)($request, 'test.device');
    $deviceCode = $start->deviceCode->reveal();
    app(DecideDeviceAuthorization::class)($request, $start->userCode->reveal(), $start->browserNonce->reveal(), true);

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
    $user->forceFill([
        'status' => 'active',
        'scalpels_issuer' => 'https://issuer.example.test',
        'scalpels_connection_id' => 'connection-fixture',
        'scalpels_id' => 'managed-device-user',
        'membership_confirmed_at' => now(),
        'membership_response_at' => now(),
        'managed_membership_status' => 'active',
        'managed_membership_generation' => 7,
        'managed_membership_roster_version' => 1,
        'managed_membership_response_sequence' => 1,
    ])->save();
    $connection = ManagedAuthConnection::current();
    app(ManagedMembershipResponses::class)->applyConfirmation(
        $connection,
        $user,
        new ManagedAuthConfirmation('managed-device-user', 'removed', 'active', 'member', 2, 2, new DateTimeImmutable('2026-09-15T12:00:00+00:00')),
    );
    Http::fake(static fn () => Http::response(['error' => 'test-created-outage'], 503));

    expect(DB::table('credential_authorizations')->sole()->status)->toBe('approved');
    $token = app(PollDeviceAuthorization::class)($request, $deviceCode);
    expect(Credential::query()->findOrFail($token->credentialId)->user_id)->toBeNull()
        ->and(DB::table('credential_authorizations')->sole()->status)->toBe('consumed');
});

it('contains installation grants through the real connection-denial chain', function (): void {
    Carbon::setTestNow('2026-09-15 12:00:00');
    $user = deviceFlowUser();
    $user->forceFill([
        'role' => 'member',
        'status' => 'active',
        'scalpels_issuer' => 'https://issuer.example.test',
        'scalpels_connection_id' => 'connection-fixture',
        'scalpels_id' => 'managed-device-user',
        'membership_confirmed_at' => now(),
        'membership_response_at' => now(),
        'managed_membership_status' => 'active',
        'managed_membership_generation' => 7,
        'managed_membership_roster_version' => 1,
        'managed_membership_response_sequence' => 1,
    ])->save();
    DeviceFlowDeclaration::$profiles = [new CredentialAuthorizationProfile(
        'test.device',
        new BoundCredentialScope('test.device', new Subject(SubjectType::Installation, 'installation-fixture'), 'installation-fixture', 'application-fixture', 'audience.example.test'),
        CredentialAuthorizationOwnership::Installation,
        [],
        null,
        600,
        5,
    )];
    $request = deviceRequest($this, $user);
    app(StartDeviceAuthorization::class)($request, 'test.device');
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
    $connection = ManagedAuthConnection::current();

    app(ManagedMembershipResponses::class)->applyConfirmation(
        $connection,
        $user,
        new ManagedAuthConfirmation('managed-device-user', 'active', 'inactive', 'member', 2, 2, new DateTimeImmutable('2026-09-15T12:00:00+00:00')),
    );

    expect(DB::table('credential_authorizations')->sole()->status)->toBe('denied')
        ->and(DB::table('credential_authorizations')->sole()->denial_reason)->toBe('connection_inactive');
});

it('contains and revokes installation state through direct subject offboarding', function (): void {
    $user = deviceFlowUser();
    $user->forceFill(['role' => 'member'])->save();
    $subject = new Subject(SubjectType::Installation, 'installation-fixture');
    DeviceFlowDeclaration::$profiles = [new CredentialAuthorizationProfile(
        'test.device',
        new BoundCredentialScope('test.device', $subject, 'installation-fixture', 'application-fixture', 'audience.example.test'),
        CredentialAuthorizationOwnership::Installation,
        [],
        null,
        600,
        5,
    )];
    $request = deviceRequest($this, $user);
    $issued = app(StartDeviceAuthorization::class)($request, 'test.device');
    app(DecideDeviceAuthorization::class)($request, $issued->userCode->reveal(), $issued->browserNonce->reveal(), true);
    $credentialId = app(PollDeviceAuthorization::class)($request, $issued->deviceCode->reveal())->credentialId;
    app(StartDeviceAuthorization::class)($request, 'test.device');

    app(OffboardSubject::class)(new OffboardOptions($subject->type, $subject->ref));

    expect(Credential::query()->findOrFail($credentialId)->revoked_at)->not->toBeNull()
        ->and(DB::table('credential_authorizations')->where('status', 'denied')->count())->toBe(1)
        ->and(DB::table('credential_authorizations')->where('status', 'consumed')->count())->toBe(1);
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
    'malformed mapping' => fn () => config(['built-for-cloud.credentials.app_purposes' => ['test.device' => true, 'test.loopback' => CredentialPurpose::Consumption->value]]),
    'unknown mapping' => fn () => config(['built-for-cloud.credentials.app_purposes' => ['test.device' => 'unknown-purpose', 'test.loopback' => CredentialPurpose::Consumption->value]]),
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
    app(DecideDeviceAuthorization::class)($request, $start->userCode->reveal(), $start->browserNonce->reveal(), true);
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

it('rejects wrong binding before managed refresh cache declaration usage or client identity effects', function (): void {
    Carbon::setTestNow('2026-09-15 12:00:00');
    $user = deviceFlowUser();
    DeviceFlowDeclaration::$profiles = [deviceProfile($user)];
    $request = deviceRequest($this, $user);
    $start = app(StartDeviceAuthorization::class)($request, 'test.device');
    app(DecideDeviceAuthorization::class)($request, $start->userCode->reveal(), $start->browserNonce->reveal(), true);
    $token = app(PollDeviceAuthorization::class)($request, $start->deviceCode->reveal());
    $secret = $token->accessToken->reveal();
    DB::table('credential_protocol_bindings')->where('credential_id', $token->credentialId)->update(['audience' => 'wrong-audience']);
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
    $user->forceFill([
        'scalpels_issuer' => 'https://issuer.example.test',
        'scalpels_connection_id' => 'connection-fixture',
        'scalpels_id' => 'managed-device-user',
        'membership_confirmed_at' => now()->subHour(),
        'managed_membership_status' => 'active',
    ])->save();
    Cache::flush();
    Http::fake(static fn () => Http::response(['error' => 'must-not-run'], 500));
    DeviceFlowDeclaration::$authorizeCalls = 0;
    $use = Request::create('/protected', 'GET', server: [
        'HTTP_AUTHORIZATION' => 'Bearer '.$secret,
        'HTTP_USER_AGENT' => 'binding-canary',
    ]);
    $refreshKey = hash('sha256', "https://issuer.example.test\0connection-fixture\0managed-device-user");

    expect(app(BoundBearerCredentialAuthenticator::class)->authenticate($use, 'test.device'))->toBeNull()
        ->and(DeviceFlowDeclaration::$authorizeCalls)->toBe(0)
        ->and(Credential::query()->findOrFail($token->credentialId)->last_used_at)->toBeNull()
        ->and(DB::table('bfc_client_identity_observations')->count())->toBe(0)
        ->and(Cache::get('bfc:managed-refresh-attempt:'.$refreshKey))->toBeNull();
    Http::assertNothingSent();
});

it('rolls back a credential collision and permits one later exchange without redelivery', function (): void {
    Carbon::setTestNow('2026-09-15 12:00:00');
    $user = deviceFlowUser();
    DeviceFlowDeclaration::$profiles = [deviceProfile($user)];
    $request = deviceRequest($this, $user);
    $start = app(StartDeviceAuthorization::class)($request, 'test.device');
    $code = $start->deviceCode->reveal();
    app(DecideDeviceAuthorization::class)($request, $start->userCode->reveal(), $start->browserNonce->reveal(), true);
    $collision = (string) Str::uuid();
    Credential::query()->create([
        'id' => $collision,
        'kind' => CredentialKind::Bearer,
        'purpose' => CredentialPurpose::Consumption,
        'subject_type' => SubjectType::UserPrincipal,
        'subject_ref' => 'collision-subject',
        'secret_hash' => hash('sha256', 'collision-secret'),
    ]);
    Str::createUuidsUsing(static fn () => Uuid::fromString($collision));

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

it('keeps approved production-action state unchanged when authority fails after grace', function (string $flow): void {
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
    Http::fake(static fn () => Http::response(['error' => 'test-created-outage'], 503));
    $user = deviceFlowUser();
    $user->forceFill([
        'role' => 'member',
        'status' => 'active',
        'scalpels_issuer' => 'https://issuer.example.test',
        'scalpels_connection_id' => 'connection-fixture',
        'scalpels_id' => 'managed-device-user',
        'membership_confirmed_at' => now()->subMinutes(29),
        'membership_checked_at' => now()->subMinutes(29),
        'membership_response_at' => now()->subMinutes(29),
        'managed_membership_status' => 'active',
        'managed_membership_role' => 'member',
        'managed_membership_generation' => 7,
        'managed_membership_roster_version' => 1,
        'managed_membership_response_sequence' => 1,
        'managed_membership_responded_at' => now()->subMinutes(29),
    ])->save();
    $purpose = $flow === 'device' ? 'test.device' : 'test.loopback';
    DeviceFlowDeclaration::$profiles = [new CredentialAuthorizationProfile(
        $purpose,
        new BoundCredentialScope($purpose, new Subject(SubjectType::Installation, 'installation-fixture'), 'installation-fixture', 'application-fixture', 'audience.example.test'),
        CredentialAuthorizationOwnership::Installation,
        [],
        null,
        600,
        5,
    )];
    $request = deviceRequest($this, $user);
    $verifier = str_repeat('v', 43);

    if ($flow === 'device') {
        $start = app(StartDeviceAuthorization::class)($request, $purpose);
        $proof = $start->deviceCode->reveal();
        app(DecideDeviceAuthorization::class)($request, $start->userCode->reveal(), $start->browserNonce->reveal(), true);
    } else {
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        $intent = app(StartLoopbackAuthorization::class)($request, $purpose, 'http://127.0.0.1:49152/callback', $challenge, 'S256', str_repeat('s', 32));
        $proof = (string) app(DecideLoopbackAuthorization::class)($request, $intent->authorizationId, $intent->browserNonce->reveal(), $intent->state, true)->authorizationCode?->reveal();
    }

    $this->travel(60)->seconds();
    Cache::flush();
    $authorizationBefore = (array) DB::table('credential_authorizations')->sole();
    $auditBefore = CredentialAuditEvent::query()->count();
    $attempt = fn () => $flow === 'device'
        ? app(PollDeviceAuthorization::class)($request, $proof)
        : app(ExchangeLoopbackAuthorization::class)($request, $proof, 'http://127.0.0.1:49152/callback', $verifier);

    expect($attempt)->toThrow(CredentialAuthorizationRefused::class, 'temporarily_unavailable')
        ->and((array) DB::table('credential_authorizations')->sole())->toBe($authorizationBefore)
        ->and(CredentialAuditEvent::query()->count())->toBe($auditBefore)
        ->and(Credential::query()->count())->toBe(0);

    $rowsBefore = DB::table('credential_authorizations')->count();
    expect(fn () => app(StartDeviceAuthorization::class)($request, $purpose))
        ->toThrow(CredentialAuthorizationRefused::class, 'temporarily_unavailable')
        ->and(DB::table('credential_authorizations')->count())->toBe($rowsBefore);
})->with(['device', 'loopback']);

it('writes nothing when current connection authority denies start', function (): void {
    DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
        'mode' => AuthorityMode::Managed->value,
        'managed_connection_status' => 'inactive',
    ]);
    $user = deviceFlowUser();
    DeviceFlowDeclaration::$profiles = [deviceProfile($user)];
    $request = deviceRequest($this, $user);

    expect(fn () => app(StartDeviceAuthorization::class)($request, 'test.device'))
        ->toThrow(CredentialAuthorizationRefused::class, 'access_denied')
        ->and(DB::table('credential_authorizations')->count())->toBe(0)
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
    Carbon::setTestNow(Carbon::parse('2026-09-15 12:00:00')->addSeconds($ttl - 1));
    expect(fn () => app(PollDeviceAuthorization::class)($request, $code))
        ->toThrow(CredentialAuthorizationRefused::class, 'authorization_pending');
    Carbon::setTestNow(Carbon::parse('2026-09-15 12:00:00')->addSeconds($ttl));
    expect(fn () => app(PollDeviceAuthorization::class)($request, $code))
        ->toThrow(CredentialAuthorizationRefused::class, 'expired_token')
        ->and(DB::table('credential_authorizations')->sole()->status)->toBe('pending');
})->with([
    'minimums' => [60, 5],
    'maximums' => [900, 30],
]);

it('increases early-poll cadence by five to thirty and admits each returned interval', function (): void {
    Carbon::setTestNow('2026-09-15 12:00:00');
    $user = deviceFlowUser();
    DeviceFlowDeclaration::$profiles = [deviceProfile($user)];
    $request = deviceRequest($this, $user);
    $code = app(StartDeviceAuthorization::class)($request, 'test.device')->deviceCode->reveal();

    expect(fn () => app(PollDeviceAuthorization::class)($request, $code))
        ->toThrow(CredentialAuthorizationRefused::class, 'authorization_pending');

    foreach ([10, 15, 20, 25, 30, 30] as $interval) {
        expect(fn () => app(PollDeviceAuthorization::class)($request, $code))
            ->toThrow(CredentialAuthorizationRefused::class, 'slow_down');
        expect((int) DB::table('credential_authorizations')->sole()->effective_interval)->toBe($interval);
        $this->travel($interval)->seconds();
        expect(fn () => app(PollDeviceAuthorization::class)($request, $code))
            ->toThrow(CredentialAuthorizationRefused::class, 'authorization_pending');
    }
});

it('returns stored denial and unknown grant before cadence effects', function (): void {
    Carbon::setTestNow('2026-09-15 12:00:00');
    $user = deviceFlowUser();
    DeviceFlowDeclaration::$profiles = [deviceProfile($user)];
    $request = deviceRequest($this, $user);
    $start = app(StartDeviceAuthorization::class)($request, 'test.device');
    $deviceCode = $start->deviceCode->reveal();
    app(DecideDeviceAuthorization::class)($request, $start->userCode->reveal(), $start->browserNonce->reveal(), false);
    $before = (array) DB::table('credential_authorizations')->sole();

    expect(fn () => app(PollDeviceAuthorization::class)($request, $deviceCode))
        ->toThrow(CredentialAuthorizationRefused::class, 'access_denied')
        ->and(fn () => app(PollDeviceAuthorization::class)($request, str_repeat('z', 43)))
        ->toThrow(CredentialAuthorizationRefused::class, 'invalid_grant')
        ->and((array) DB::table('credential_authorizations')->sole())->toBe($before);
});

it('turns profile drift into one terminal denial without minting', function (): void {
    Carbon::setTestNow('2026-09-15 12:00:00');
    $user = deviceFlowUser();
    DeviceFlowDeclaration::$profiles = [deviceProfile($user)];
    $request = deviceRequest($this, $user);
    $start = app(StartDeviceAuthorization::class)($request, 'test.device');
    app(DecideDeviceAuthorization::class)($request, $start->userCode->reveal(), $start->browserNonce->reveal(), true);
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

it('turns stored lifetime and cadence drift into the same terminal denial', function (string $dimension): void {
    Carbon::setTestNow('2026-09-15 12:00:00');
    $user = deviceFlowUser();
    DeviceFlowDeclaration::$profiles = [deviceProfile($user)];
    $request = deviceRequest($this, $user);
    $start = app(StartDeviceAuthorization::class)($request, 'test.device');
    app(DecideDeviceAuthorization::class)($request, $start->userCode->reveal(), $start->browserNonce->reveal(), true);
    $profile = deviceProfile($user);
    DeviceFlowDeclaration::$profiles = [new CredentialAuthorizationProfile(
        'test.device',
        $profile->scope,
        CredentialAuthorizationOwnership::Personal,
        [],
        $profile->expiresAt,
        $dimension === 'lifetime' ? 60 : 600,
        $dimension === 'cadence' ? 10 : 5,
    )];

    expect(fn () => app(PollDeviceAuthorization::class)($request, $start->deviceCode->reveal()))
        ->toThrow(CredentialAuthorizationRefused::class, 'access_denied')
        ->and(DB::table('credential_authorizations')->sole()->status)->toBe('denied')
        ->and(Credential::query()->count())->toBe(0);
})->with(['lifetime', 'cadence']);

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
