<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\BoundCredentialScope;
use ArtisanBuild\BuiltForCloud\BrowserCredentialAuthorizationStore;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationOwnership;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationProfile;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\DeviceFlowDeclaration;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\DB;

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
        ->and(DB::table('credentials')->count())->toBe(0);

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
        ->and(DB::table('credentials')->count())->toBe(0);

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
