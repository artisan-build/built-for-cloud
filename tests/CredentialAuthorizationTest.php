<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\DecideDeviceAuthorization;
use ArtisanBuild\BuiltForCloud\Actions\DecideLoopbackAuthorization;
use ArtisanBuild\BuiltForCloud\Actions\ExchangeLoopbackAuthorization;
use ArtisanBuild\BuiltForCloud\Actions\PollDeviceAuthorization;
use ArtisanBuild\BuiltForCloud\Actions\StartDeviceAuthorization;
use ArtisanBuild\BuiltForCloud\Actions\StartLoopbackAuthorization;
use ArtisanBuild\BuiltForCloud\Auth\CredentialResolver;
use ArtisanBuild\BuiltForCloud\BoundBearerCredentialAuthenticator;
use ArtisanBuild\BuiltForCloud\BoundCredentialScope;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAlgorithm;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationOwnership;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationProfile;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialMaterialRole;
use ArtisanBuild\BuiltForCloud\CredentialProtocolBinding;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialAuthorizationRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\StandaloneAccess;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\DeviceFlowDeclaration;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;

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
