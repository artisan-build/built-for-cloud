<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\DecideLoopbackAuthorization;
use ArtisanBuild\BuiltForCloud\Actions\StartLoopbackAuthorization;
use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\BoundCredentialScope;
use ArtisanBuild\BuiltForCloud\BrowserCredentialAuthorizationStore;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationOwnership;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationPolicy;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationProfile;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\Http\Controllers\LoopbackAuthorizations;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\DeviceFlowDeclaration;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Route;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    DeviceFlowDeclaration::$profiles = [];
    DeviceFlowDeclaration::$authorizeCalls = 0;
    DeviceFlowDeclaration::$resolvedSubject = null;
    DeviceFlowDeclaration::$selfServiceAbilities = [];
    DeviceFlowDeclaration::$selfServiceKinds = [CredentialKind::Bearer];
    config([
        'built-for-cloud.credentials.declaration' => DeviceFlowDeclaration::class,
        'built-for-cloud.credentials.app_purposes' => [
            'http.device' => CredentialPurpose::Consumption->value,
            'http.loopback' => CredentialPurpose::Consumption->value,
        ],
    ]);
});

function httpAuthorizationUser(string $email = 'http-device@example.test'): User
{
    return User::query()->create([
        'name' => 'HTTP device operator',
        'email' => $email,
        'password' => bcrypt('test-created-password'),
    ]);
}

function httpAuthorizationProfile(User $user, string $purpose): CredentialAuthorizationProfile
{
    $profile = new CredentialAuthorizationProfile(
        $purpose,
        new BoundCredentialScope(
            $purpose,
            new Subject(SubjectType::UserPrincipal, 'http-user:'.$user->getKey()),
            'http-installation-test',
            'http-application-test',
            'https://http-audience.example.test',
        ),
        CredentialAuthorizationOwnership::Personal,
        [],
        now()->addDay(),
        600,
        5,
    );
    DeviceFlowDeclaration::$profiles = [$profile];
    DeviceFlowDeclaration::$resolvedSubject = $profile->scope->subject;

    return $profile;
}

/** @return array<string, string> */
function authorizationHiddenInputs(string $html, string $action): array
{
    preg_match('/<form[^>]*>.*?name="action" value="'.preg_quote($action, '/').'".*?<\/form>/s', $html, $form);
    preg_match_all('/name="([^"]+)" value="([^"]*)"/', $form[0] ?? '', $inputs, PREG_SET_ORDER);

    return array_column($inputs, 2, 1);
}

it('refuses malformed and foreign device HTTP attempts before completing the exact wire', function (): void {
    $user = httpAuthorizationUser();
    httpAuthorizationProfile($user, 'http.device');

    $this->postJson('/bfc/device-authorizations', ['app_purpose' => 'http.device'])
        ->assertUnauthorized();
    expect(DB::table('credential_authorizations')->count())->toBe(0);

    $this->actingAsVersioned($user, 'web');
    $this->call('POST', '/bfc/device-authorizations', server: ['CONTENT_TYPE' => 'text/plain'], content: '{}')
        ->assertStatus(400)
        ->assertExactJson(['error' => 'invalid_request']);
    $this->postJson('/bfc/device-authorizations', [
        'app_purpose' => 'http.device',
        'subject_ref' => 'request-authored-subject',
    ])->assertStatus(400)->assertExactJson(['error' => 'invalid_request']);
    expect(DB::table('credential_authorizations')->count())->toBe(0);

    $start = $this->postJson('/bfc/device-authorizations', [
        'app_purpose' => 'http.device',
        'label' => 'HTTP-created device',
    ])->assertCreated()
        ->assertHeader('Cache-Control', 'no-store, private')
        ->assertHeader('Pragma', 'no-cache')
        ->assertJsonStructure(['device_code', 'user_code', 'verification_uri', 'expires_in', 'interval']);
    expect(array_keys($start->json()))->toBe([
        'device_code', 'user_code', 'verification_uri', 'expires_in', 'interval',
    ])->and($start->json('verification_uri'))->toBe(url('/bfc/device'));

    $deviceCode = $start->json('device_code');
    $userCode = $start->json('user_code');
    expect($deviceCode)->toBeString()->and($userCode)->toBeString();

    $serialized = serialize(app('session')->driver()->all());
    $ciphertexts = app(BrowserCredentialAuthorizationStore::class)->serializedCiphertexts(request());
    expect($ciphertexts)->toHaveCount(1)
        ->and($serialized)->not->toContain($deviceCode, $userCode)
        ->and($ciphertexts[0])->not->toContain($userCode);

    $this->postJson('/bfc/device/token', ['device_code' => $deviceCode, 'extra' => true])
        ->assertStatus(400)->assertExactJson(['error' => 'invalid_request']);
    expect(DB::table('credential_authorizations')->value('last_polled_at'))->toBeNull();

    $this->postJson('/bfc/device/token', ['device_code' => $deviceCode])
        ->assertStatus(400)->assertExactJson(['error' => 'authorization_pending']);

    $session = app('session')->driver()->all();
    $cleanRequest = Request::create('/bfc/device');
    $cleanRequest->setUserResolver(static fn (): User => $user);
    $cleanRequest->setLaravelSession(new Store('clean-context', new ArraySessionHandler(120)));
    expect(app(BrowserCredentialAuthorizationStore::class)->deviceBindings($cleanRequest))->toBe([]);

    $this->withSession($session);
    $page = $this->get('/bfc/device')
        ->assertOk()
        ->assertSee('data-testid="device-authorization-list"', false)
        ->assertSee($userCode)
        ->assertSee('HTTP-created device')
        ->assertSee('https://http-audience.example.test');
    $approve = authorizationHiddenInputs($page->getContent(), 'approve');
    $sessionCookie = $page->getCookie((string) config('session.cookie'));
    expect($sessionCookie)->not->toBeNull();

    $this->post('/bfc/device', [
        'user_code' => $userCode,
        'action' => 'approve',
        'submission_nonce' => str_repeat('0', 64),
    ])->assertNotFound();
    expect(DB::table('credential_authorizations')->value('status'))->toBe('pending')
        ->and(DB::table('credentials')->count())->toBe(0);

    $this->withCookie((string) config('session.cookie'), $sessionCookie->getValue())
        ->post('/bfc/device', $approve)
        ->assertOk()
        ->assertSee('data-testid="device-authorization-result"', false)
        ->assertSee('approved');
    expect(DB::table('credential_authorizations')->value('status'))->toBe('approved')
        ->and(DB::table('credentials')->count())->toBe(0)
        ->and(app(BrowserCredentialAuthorizationStore::class)->serializedCiphertexts(request()))->toBe([]);

    $this->postJson('/bfc/device/token', ['device_code' => $deviceCode])
        ->assertStatus(400)
        ->assertJsonPath('error', 'slow_down')
        ->assertJsonPath('interval', 10);
    $this->travel(10)->seconds();
    $token = $this->postJson('/bfc/device/token', ['device_code' => $deviceCode])
        ->assertOk()
        ->assertJsonPath('token_type', 'Bearer')
        ->assertJsonPath('app_purpose', 'http.device');
    expect(array_keys($token->json()))->toBe([
        'access_token', 'token_type', 'credential_id', 'app_purpose', 'expires_at',
    ])->and(DB::table('credentials')->count())->toBe(1);

    $this->postJson('/bfc/device/token', ['device_code' => $deviceCode])
        ->assertStatus(400)->assertExactJson(['error' => 'invalid_grant']);
});

it('refuses malformed callback and PKCE attempts before one loopback exchange', function (): void {
    $user = httpAuthorizationUser('http-loopback@example.test');
    httpAuthorizationProfile($user, 'http.loopback');
    $this->actingAsVersioned($user, 'web');
    $verifier = str_repeat('v', 43);
    $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    $state = str_repeat('s', 32);

    $bad = http_build_query([
        'app_purpose' => 'http.loopback',
        'redirect_uri' => 'https://example.test:49152/callback',
        'code_challenge' => $challenge,
        'code_challenge_method' => 'S256',
        'state' => $state,
    ]);
    $this->get('/bfc/loopback/authorize?'.$bad)->assertNotFound();
    expect(DB::table('credential_authorizations')->count())->toBe(0);

    $redirect = 'http://127.0.0.1:49152/callback?test=created';
    $query = http_build_query([
        'app_purpose' => 'http.loopback',
        'redirect_uri' => $redirect,
        'code_challenge' => $challenge,
        'code_challenge_method' => 'S256',
        'state' => $state,
        'label' => 'HTTP loopback client',
    ]);
    $page = $this->get('/bfc/loopback/authorize?'.$query)
        ->assertOk()
        ->assertSee('data-testid="device-authorization-loopback"', false)
        ->assertSee('127.0.0.1:49152')
        ->assertSee('HTTP loopback client');
    $ciphertexts = app(BrowserCredentialAuthorizationStore::class)->serializedCiphertexts(request());
    $sealed = json_decode(app('encrypter')->decrypt($ciphertexts[0], false), true, flags: JSON_THROW_ON_ERROR);
    expect(array_keys($sealed))->toBe(['flow', 'authorization_id', 'browser_nonce', 'state'])
        ->and($sealed)->not->toHaveKeys(['app_purpose', 'redirect_uri', 'code_challenge', 'label']);
    $approve = authorizationHiddenInputs($page->getContent(), 'approve');
    expect($approve)->toHaveKeys(['action', 'submission_nonce']);
    $sessionCookie = $page->getCookie((string) config('session.cookie'));
    expect($sessionCookie)->not->toBeNull();
    $decision = $this->withCookie((string) config('session.cookie'), $sessionCookie->getValue())
        ->post('/bfc/loopback/authorize', $approve)
        ->assertStatus(303);
    $location = (string) $decision->headers->get('Location');
    parse_str((string) parse_url($location, PHP_URL_QUERY), $callback);
    expect($callback['state'] ?? null)->toBe($state)
        ->and($callback['code'] ?? null)->toMatch('/^[A-Za-z0-9_-]{43}$/')
        ->and(DB::table('credentials')->count())->toBe(0)
        ->and(app(BrowserCredentialAuthorizationStore::class)->serializedCiphertexts(request()))->toBe([]);

    $this->postJson('/bfc/loopback/token', [
        'code' => $callback['code'],
        'redirect_uri' => $redirect,
        'code_verifier' => str_repeat('x', 43),
    ])->assertStatus(400)->assertExactJson(['error' => 'invalid_grant']);
    $this->postJson('/bfc/loopback/token', [
        'code' => $callback['code'],
        'redirect_uri' => 'http://127.0.0.1:49153/callback?test=created',
        'code_verifier' => $verifier,
    ])->assertStatus(400)->assertExactJson(['error' => 'invalid_grant']);

    $token = $this->postJson('/bfc/loopback/token', [
        'code' => $callback['code'],
        'redirect_uri' => $redirect,
        'code_verifier' => $verifier,
    ])->assertOk()->assertJsonPath('app_purpose', 'http.loopback');
    expect($token->json('access_token'))->toBeString()
        ->and(DB::table('credentials')->count())->toBe(1);

    $this->postJson('/bfc/loopback/token', [
        'code' => $callback['code'],
        'redirect_uri' => $redirect,
        'code_verifier' => $verifier,
    ])->assertStatus(400)->assertExactJson(['error' => 'invalid_grant']);
});

it('refuses a ninth live browser binding without evicting the existing grants', function (): void {
    $user = httpAuthorizationUser('http-bound@example.test');
    httpAuthorizationProfile($user, 'http.device');
    $this->actingAsVersioned($user, 'web');

    for ($i = 0; $i < BrowserCredentialAuthorizationStore::MAX_LIVE_BINDINGS; $i++) {
        $this->postJson('/bfc/device-authorizations', [
            'app_purpose' => 'http.device',
            'label' => 'Bound grant '.$i,
        ])->assertCreated();
    }

    $this->postJson('/bfc/device-authorizations', ['app_purpose' => 'http.device'])
        ->assertStatus(503)
        ->assertExactJson(['error' => 'temporarily_unavailable']);
    expect(DB::table('credential_authorizations')->count())->toBe(BrowserCredentialAuthorizationStore::MAX_LIVE_BINDINGS)
        ->and(app(BrowserCredentialAuthorizationStore::class)->serializedCiphertexts(request()))
        ->toHaveCount(BrowserCredentialAuthorizationStore::MAX_LIVE_BINDINGS);
});

it('removes a terminal profile-withdrawn binding without consuming its submission nonce', function (): void {
    $user = httpAuthorizationUser('http-withdrawn@example.test');
    httpAuthorizationProfile($user, 'http.device');
    $this->actingAsVersioned($user, 'web');

    $start = $this->postJson('/bfc/device-authorizations', ['app_purpose' => 'http.device'])->assertCreated();
    $page = $this->get('/bfc/device')->assertOk();
    $approve = authorizationHiddenInputs($page->getContent(), 'approve');
    $nonceHash = hash('sha256', $approve['submission_nonce']);
    DeviceFlowDeclaration::$profiles = [];

    $this->post('/bfc/device', $approve)->assertNotFound();

    expect(DB::table('credential_authorizations')->value('status'))->toBe('denied')
        ->and(DB::table('credential_authorizations')->value('denial_reason'))->toBe('profile_withdrawn')
        ->and(DB::table('bfc_submission_nonces')->where('nonce_hash', $nonceHash)->exists())->toBeTrue()
        ->and(app(BrowserCredentialAuthorizationStore::class)->serializedCiphertexts(request()))->toBe([])
        ->and(DB::table('credentials')->count())->toBe(0)
        ->and($start->json('device_code'))->toBeString();
});

it('rejects transport-limited polls before cadence or authorization effects', function (): void {
    $user = httpAuthorizationUser('http-limited@example.test');
    httpAuthorizationProfile($user, 'http.device');
    $this->actingAsVersioned($user, 'web');
    $start = $this->postJson('/bfc/device-authorizations', ['app_purpose' => 'http.device'])->assertCreated();
    $before = (array) DB::table('credential_authorizations')->sole();
    $authorizeCalls = DeviceFlowDeclaration::$authorizeCalls;

    for ($attempt = 0; $attempt < 120; $attempt++) {
        $this->postJson('/bfc/device/token', ['unexpected' => $attempt])
            ->assertStatus(400)
            ->assertExactJson(['error' => 'invalid_request']);
    }

    $response = $this->postJson('/bfc/device/token', ['device_code' => $start->json('device_code')])
        ->assertStatus(429)
        ->assertJsonPath('error', 'slow_down');
    $after = (array) DB::table('credential_authorizations')->sole();

    expect((int) $response->headers->get('Retry-After'))->toBeBetween(1, 30)
        ->and($after['last_polled_at'])->toBe($before['last_polled_at'])
        ->and($after['effective_interval'])->toBe($before['effective_interval'])
        ->and($after['status'])->toBe($before['status'])
        ->and(DeviceFlowDeclaration::$authorizeCalls)->toBe($authorizeCalls)
        ->and(DB::table('credential_audit_events')->where('credential_authorization_id', $after['id'])->count())->toBe(1);
});

it('shares one package-global token bucket while separating device and loopback source buckets', function (): void {
    $deviceRoute = Route::getRoutes()->getByName('bfc.device.token');
    $loopbackRoute = Route::getRoutes()->getByName('bfc.loopback.token');
    $limiter = RateLimiter::limiter('bfc-authorization-token');
    expect($deviceRoute)->not->toBeNull()
        ->and($loopbackRoute)->not->toBeNull()
        ->and($deviceRoute->gatherMiddleware())->toContain('throttle:bfc-authorization-token')
        ->and($loopbackRoute->gatherMiddleware())->toContain('throttle:bfc-authorization-token')
        ->and($limiter)->toBeCallable();

    $device = Request::create('/bfc/device/token', 'POST', server: ['REMOTE_ADDR' => '2001:db8:1:2::1']);
    $loopback = Request::create('/bfc/loopback/token', 'POST', server: ['REMOTE_ADDR' => '2001:db8:1:2::abcd']);
    $deviceLimits = $limiter($device);
    $loopbackLimits = $limiter($loopback);

    expect($deviceLimits[0]->key)->toBe('bfc-device-token|2001:db8:1:2::/64')
        ->and($loopbackLimits[0]->key)->toBe('bfc-loopback-token|2001:db8:1:2::/64')
        ->and($deviceLimits[1]->key)->toBe('bfc-authorization-token-global')
        ->and($loopbackLimits[1]->key)->toBe($deviceLimits[1]->key)
        ->and($deviceLimits[1]->maxAttempts)->toBe(6000)
        ->and($loopbackLimits[1]->maxAttempts)->toBe(6000);
});

it('actively removes terminal and unsealable bindings while serving both GET surfaces', function (): void {
    $user = httpAuthorizationUser('http-cleanup@example.test');
    httpAuthorizationProfile($user, 'http.device');
    $this->actingAsVersioned($user, 'web');
    $device = $this->postJson('/bfc/device-authorizations', ['app_purpose' => 'http.device'])->assertCreated();
    $session = app('session')->driver();
    $deviceCiphertext = app(BrowserCredentialAuthorizationStore::class)->serializedCiphertexts(request())[0];
    $session->put('bfc_credential_authorizations', [$deviceCiphertext, 'test-created-unsealable-ciphertext']);

    $this->get('/bfc/device')->assertOk()->assertSee((string) $device->json('user_code'));
    expect(app(BrowserCredentialAuthorizationStore::class)->serializedCiphertexts(request()))->toBe([$deviceCiphertext]);

    DB::table('credential_authorizations')->where('device_code_hash', hash('sha256', (string) $device->json('device_code')))->update([
        'status' => 'denied',
        'denial_reason' => 'authority_denied',
        'decided_at' => now(),
    ]);
    $this->get('/bfc/device')->assertNotFound();
    expect(app(BrowserCredentialAuthorizationStore::class)->serializedCiphertexts(request()))->toBe([]);

    httpAuthorizationProfile($user, 'http.loopback');
    $verifier = str_repeat('v', 43);
    $query = http_build_query([
        'app_purpose' => 'http.loopback',
        'redirect_uri' => 'http://127.0.0.1:49152/cleanup',
        'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='),
        'code_challenge_method' => 'S256',
        'state' => str_repeat('c', 32),
    ]);
    $this->get('/bfc/loopback/authorize?'.$query)->assertOk();
    $loopbackCiphertext = app(BrowserCredentialAuthorizationStore::class)->serializedCiphertexts(request())[0];
    $session->put('bfc_credential_authorizations', [$loopbackCiphertext, 'another-unsealable-ciphertext']);
    $session->put('bfc_selected_loopback_authorization', 'stale-loopback-selection');
    $loopbackRequest = Request::create('/bfc/loopback/authorize?'.$query);
    $loopbackRequest->setLaravelSession($session);
    $loopbackRequest->setUserResolver(static fn (): User => $user);
    $loopbackResponse = app(LoopbackAuthorizations::class)->show(
        $loopbackRequest,
        app(StartLoopbackAuthorization::class),
        app(BrowserCredentialAuthorizationStore::class),
        app(CredentialAuthorizationPolicy::class),
    );

    $cleanedLoopbackCiphertexts = app(BrowserCredentialAuthorizationStore::class)->serializedCiphertexts($loopbackRequest);
    expect($loopbackResponse->getStatusCode())->toBe(200)
        ->and($cleanedLoopbackCiphertexts)->not->toContain('another-unsealable-ciphertext')
        ->and($session->get('bfc_selected_loopback_authorization'))->toBeIn($cleanedLoopbackCiphertexts)
        ->not->toBe('stale-loopback-selection');
});

it('keeps managed loopback authority refusals terminal or retryable without consuming the decision nonce', function (): void {
    $user = httpAuthorizationUser('http-managed-loopback@example.test');
    httpAuthorizationProfile($user, 'http.loopback');
    $this->actingAsVersioned($user, 'web');
    $verifier = str_repeat('v', 43);
    $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    $query = static fn (string $state, int $port): string => http_build_query([
        'app_purpose' => 'http.loopback',
        'redirect_uri' => "http://127.0.0.1:{$port}/managed",
        'code_challenge' => $challenge,
        'code_challenge_method' => 'S256',
        'state' => $state,
    ]);

    $positivePage = $this->get('/bfc/loopback/authorize?'.$query(str_repeat('p', 32), 49152))->assertOk();
    $positive = authorizationHiddenInputs($positivePage->getContent(), 'approve');
    $positiveCookie = $positivePage->getCookie((string) config('session.cookie'));
    expect($positiveCookie)->not->toBeNull();
    $positiveHash = hash('sha256', $positive['submission_nonce']);
    $this->withCookie((string) config('session.cookie'), $positiveCookie->getValue())
        ->post('/bfc/loopback/authorize', $positive)
        ->assertStatus(303);
    expect(DB::table('bfc_submission_nonces')->where('nonce_hash', $positiveHash)->exists())->toBeFalse();

    $deniedPage = $this->get('/bfc/loopback/authorize?'.$query(str_repeat('d', 32), 49153))->assertOk();
    $denied = authorizationHiddenInputs($deniedPage->getContent(), 'approve');
    $deniedHash = hash('sha256', $denied['submission_nonce']);
    DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
        'mode' => AuthorityMode::Managed->value,
        'generation' => 7,
        'issuer' => 'https://issuer.example.test',
        'connection_id' => 'connection-fixture',
        'organization_id' => 'organization-fixture',
        'installation_id' => 'installation-fixture',
        'authority_base_url' => 'https://authority.example.test',
        'managed_connection_status' => 'inactive',
    ]);
    $denialRequest = Request::create('/bfc/loopback/authorize', 'POST', $denied);
    $denialRequest->setLaravelSession(app('session')->driver());
    $denialRequest->setUserResolver(static fn (): User => $user);
    $denialResponse = app(LoopbackAuthorizations::class)->decide(
        $denialRequest,
        app(DecideLoopbackAuthorization::class),
        app(BrowserCredentialAuthorizationStore::class),
    );

    expect($denialResponse->getStatusCode())->toBe(303)
        ->and($denialResponse->headers->get('Location'))->toContain('error=access_denied', 'state='.str_repeat('d', 32))
        ->and(DB::table('credential_authorizations')->where('redirect_uri', 'http://127.0.0.1:49153/managed')->value('status'))->toBe('denied')
        ->and(DB::table('bfc_submission_nonces')->where('nonce_hash', $deniedHash)->exists())->toBeTrue()
        ->and(DB::table('credentials')->count())->toBe(0);

    InstallationAuthority::change(InstallationAuthority::current(), AuthorityMode::Standalone);
    $retryPage = $this->get('/bfc/loopback/authorize?'.$query(str_repeat('r', 32), 49154))->assertOk();
    $retry = authorizationHiddenInputs($retryPage->getContent(), 'approve');
    $retryHash = hash('sha256', $retry['submission_nonce']);
    InstallationAuthority::change(InstallationAuthority::current(), AuthorityMode::Managed);
    DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update(['managed_connection_status' => 'active']);
    config(['built-for-cloud.managed.client_secret' => 'fixture-client-secret']);
    $user->forceFill([
        'status' => 'active',
        'scalpels_issuer' => 'https://issuer.example.test',
        'scalpels_connection_id' => 'connection-fixture',
        'scalpels_id' => 'managed-loopback-user',
        'membership_confirmed_at' => now()->subMinutes(31),
        'membership_response_at' => now()->subMinutes(31),
        'managed_membership_status' => 'active',
    ])->save();
    Cache::flush();
    Http::fake(static fn () => Http::response(['error' => 'test-created-outage'], 503));
    $retryRequest = Request::create('/bfc/loopback/authorize', 'POST', $retry);
    $retryRequest->setLaravelSession(app('session')->driver());
    $retryRequest->setUserResolver(static fn (): User => $user);
    $retryResponse = app(LoopbackAuthorizations::class)->decide(
        $retryRequest,
        app(DecideLoopbackAuthorization::class),
        app(BrowserCredentialAuthorizationStore::class),
    );

    expect($retryResponse->getStatusCode())->toBe(503)
        ->and($retryResponse->headers->get('Retry-After'))->toBe('5')
        ->and(DB::table('credential_authorizations')->where('redirect_uri', 'http://127.0.0.1:49154/managed')->value('status'))->toBe('pending')
        ->and(DB::table('bfc_submission_nonces')->where('nonce_hash', $retryHash)->exists())->toBeTrue()
        ->and(app(BrowserCredentialAuthorizationStore::class)->serializedCiphertexts($retryRequest))->toHaveCount(1)
        ->and(DB::table('credentials')->count())->toBe(0);
});
