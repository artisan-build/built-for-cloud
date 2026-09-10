<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManagedAuthentication;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureManagedAuthority;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureStandaloneAuthority;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\ManagedAuthClient;
use ArtisanBuild\BuiltForCloud\ManagedHandoff;
use ArtisanBuild\BuiltForCloud\StandaloneAccess;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\ManagedAuthorityFixture;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;

uses(RefreshDatabase::class);

function managedConnection(string $baseUrl = 'https://authority.example.test'): array
{
    $secret = bin2hex(random_bytes(32));
    DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
        'mode' => AuthorityMode::Managed->value,
        'generation' => 7,
        'issuer' => 'https://issuer.example.test',
        'connection_id' => 'connection-fixture',
        'organization_id' => 'organization-fixture',
        'installation_id' => 'installation-fixture',
        'authority_base_url' => $baseUrl,
    ]);
    config([
        'built-for-cloud.managed.client_secret' => $secret,
        'built-for-cloud.managed.ca_bundle' => null,
    ]);

    return compact('baseUrl', 'secret');
}

function managedFixture(string $baseUrl, string $secret): ManagedAuthorityFixture
{
    return new ManagedAuthorityFixture(
        $baseUrl,
        $secret,
        'https://issuer.example.test',
        'connection-fixture',
        'organization-fixture',
        'installation-fixture',
        7,
    );
}

/** @return array<string, mixed> */
function validExchangeBody(array $overrides = []): array
{
    return array_merge([
        'contract_version' => ManagedAuthClient::CONTRACT_VERSION,
        'issuer' => 'https://issuer.example.test',
        'connection_id' => 'connection-fixture',
        'organization_id' => 'organization-fixture',
        'installation_id' => 'installation-fixture',
        'authority_generation' => 7,
        'roster_version' => 8,
        'response_sequence' => 13,
        'responded_at' => now()->toAtomString(),
        'scalpels_id' => 'subject-fixture',
        'membership_id' => 'membership-fixture',
        'membership_status' => 'active',
        'connection_status' => 'active',
        'role' => 'member',
        'display_name' => 'Fixture Member',
        'contact_email' => 'fixture-member@example.test',
        'contact_email_verified' => true,
    ], $overrides);
}

function managedUser(): User
{
    $user = User::query()->create([
        'name' => 'Existing Managed Member',
        'email' => 'existing-managed@example.test',
    ]);
    $user->forceFill([
        'role' => 'member',
        'scalpels_issuer' => 'https://issuer.example.test',
        'scalpels_connection_id' => 'connection-fixture',
        'scalpels_id' => 'subject-fixture',
    ])->save();

    return $user;
}

/** @return array{state: string, nonce: string, session_id: string} */
function beginManagedHandoff(ManagedAuthorityFixture $fixture): array
{
    Http::fake(fn (ClientRequest $request) => $fixture->respond($request));
    $response = test()->get('/bfc/managed/login');
    expect($fixture->calls)->toHaveCount(1)
        ->and(DB::table('bfc_managed_handoffs')->count())->toBe(1)
        ->and(session(ManagedHandoff::SESSION_NONCE_KEY))->toBeString();
    $response->assertRedirect();
    $url = (string) $response->headers->get('Location');
    parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
    $state = $query['state'] ?? null;
    $nonce = session(ManagedHandoff::SESSION_NONCE_KEY);

    expect($state)->toBeString()->toHaveLength(43)
        ->and($nonce)->toBeString()->toHaveLength(43);

    return [
        'state' => $state,
        'nonce' => $nonce,
        'session_id' => session()->getId(),
    ];
}

it('creates an opaque hash-only handoff from stored connection facts and ignores every browser channel', function (): void {
    ['baseUrl' => $baseUrl, 'secret' => $secret] = managedConnection();
    $fixture = managedFixture($baseUrl, $secret);
    Http::fake(fn (ClientRequest $request) => $fixture->respond($request));

    $response = $this
        ->withHeader('X-Bfc-Connection', 'header-sentinel')
        ->withCookie('bfc_connection', 'cookie-sentinel')
        ->withSession(['connection_id' => 'session-sentinel'])
        ->call(
            'GET',
            '/bfc/managed/login',
            ['connection_id' => 'query-sentinel', 'issuer' => 'query-issuer'],
            [],
            [],
            ['CONTENT_TYPE' => 'application/json'],
            json_encode(['installation_id' => 'body-sentinel'], JSON_THROW_ON_ERROR),
        );

    $response->assertRedirect();
    $url = (string) $response->headers->get('Location');
    expect(strtok($url, '?'))->toBe($baseUrl.ManagedAuthClient::AUTHORIZE_PATH);
    parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
    expect(array_keys($query))->toBe(['state']);
    $state = $query['state'];
    $nonce = session(ManagedHandoff::SESSION_NONCE_KEY);
    $row = DB::table('bfc_managed_handoffs')->first();

    expect($fixture->calls)->toHaveCount(1)
        ->and($fixture->calls[0]['body'])->toBe([
            'connection_id' => 'connection-fixture',
            'installation_id' => 'installation-fixture',
            'request_id' => $state,
        ])
        ->and($row->state_hash)->toBe(hash('sha256', $state))
        ->and($row->session_nonce_hash)->toBe(hash('sha256', $nonce))
        ->and(json_encode($row, JSON_THROW_ON_ERROR))->not->toContain($state, $nonce, 'sentinel');
});

it('caps correlation expiry at 300 seconds and lets authority expiry shorten it', function (int $seconds, int $expected): void {
    Carbon\CarbonImmutable::setTestNow('2026-09-10T12:00:00+00:00');
    ['baseUrl' => $baseUrl] = managedConnection();
    Http::fake(function (ClientRequest $request) use ($baseUrl, $seconds) {
        return Http::response([
            'contract_version' => ManagedAuthClient::CONTRACT_VERSION,
            'request_id' => $request->data()['request_id'],
            'authorization_url' => $baseUrl.ManagedAuthClient::AUTHORIZE_PATH,
            'expires_at' => now()->addSeconds($seconds)->toAtomString(),
        ]);
    });

    $this->get('/bfc/managed/login')->assertRedirect();
    $expiry = new Carbon\CarbonImmutable((string) DB::table('bfc_managed_handoffs')->value('expires_at'));
    expect(now()->diffInSeconds($expiry))->toBe((float) $expected);
})->with([[90, 90], [900, 300]]);

it('binds callback to the initiating browser, claims once, exchanges server-side, and regenerates login', function (): void {
    ['baseUrl' => $baseUrl, 'secret' => $secret] = managedConnection();
    $fixture = managedFixture($baseUrl, $secret);
    $user = managedUser();
    $handoff = beginManagedHandoff($fixture);

    $this->flushSession();
    $wrongBrowser = $this->get('/bfc/managed/callback?'.http_build_query([
        'state' => $handoff['state'],
        'code' => 'valid-code-for-wrong-browser',
    ]));
    $wrongBrowser->assertStatus(404)->assertSeeText('Not Found');
    expect(DB::table('bfc_managed_handoffs')->value('consumed_at'))->toBeNull()
        ->and($fixture->calls)->toHaveCount(1);

    $success = $this->withSession([
        ManagedHandoff::SESSION_NONCE_KEY => $handoff['nonce'],
        'preexisting' => 'browser-state',
    ])->get('/bfc/managed/callback?'.http_build_query([
        'state' => $handoff['state'],
        'code' => 'valid-exchange-code',
        'issuer' => 'ignored-callback-sentinel',
    ]));
    $success->assertRedirect('/');

    expect(DB::table('bfc_managed_handoffs')->value('consumed_at'))->not->toBeNull()
        ->and($fixture->calls)->toHaveCount(2)
        ->and($fixture->calls[1]['body'])->toBe([
            'connection_id' => 'connection-fixture',
            'installation_id' => 'installation-fixture',
            'code' => 'valid-exchange-code',
        ])
        ->and(session()->getId())->not->toBe($handoff['session_id'])
        ->and(session(StandaloneAccess::SESSION_VERSION_KEY))->toBe($user->refresh()->auth_session_version)
        ->and(session(ManagedHandoff::SESSION_NONCE_KEY))->toBeNull()
        ->and(auth('web')->id())->toBe($user->getKey());

    $replay = $this->withSession([ManagedHandoff::SESSION_NONCE_KEY => $handoff['nonce']])
        ->get('/bfc/managed/callback?'.http_build_query([
            'state' => $handoff['state'],
            'code' => 'another-valid-code',
        ]));
    $replay->assertStatus(404)->assertSeeText('Not Found');
    expect($fixture->calls)->toHaveCount(2);
});

it('refuses foreign authorization origins, insecure bases, and missing client credentials without correlation writes', function (string $case): void {
    ['baseUrl' => $baseUrl] = managedConnection($case === 'insecure' ? 'http://authority.example.test' : 'https://authority.example.test');

    if ($case === 'missing-credential') {
        config(['built-for-cloud.managed.client_secret' => null]);
    }

    Http::fake(Http::response([
        'contract_version' => ManagedAuthClient::CONTRACT_VERSION,
        'request_id' => 'irrelevant',
        'authorization_url' => 'https://foreign.example.test'.ManagedAuthClient::AUTHORIZE_PATH,
        'expires_at' => now()->addMinute()->toAtomString(),
    ]));

    $this->get('/bfc/managed/login')->assertStatus(404)->assertSeeText('Not Found');
    expect(DB::table('bfc_managed_handoffs')->count())->toBe(0);

    if ($case !== 'foreign-origin') {
        Http::assertNothingSent();
    }
})->with(['foreign-origin', 'insecure', 'missing-credential']);

it('enforces every invariant response binding before user or session effects', function (string $field, mixed $value): void {
    ['baseUrl' => $baseUrl, 'secret' => $secret] = managedConnection();
    $fixture = managedFixture($baseUrl, $secret);
    $user = managedUser();
    $handoff = beginManagedHandoff($fixture);
    $fixture->exchangeOverrides = [$field => $value];

    $before = $user->fresh()->toArray();
    $response = $this->withSession([ManagedHandoff::SESSION_NONCE_KEY => $handoff['nonce']])
        ->get('/bfc/managed/callback?'.http_build_query(['state' => $handoff['state'], 'code' => 'valid-code']));

    $response->assertStatus(404)->assertSeeText('Not Found');
    expect($user->fresh()->toArray())->toBe($before)
        ->and(auth('web')->check())->toBeFalse()
        ->and(session(StandaloneAccess::SESSION_VERSION_KEY))->toBeNull();
})->with([
    ['contract_version', 'managed-auth-v2'],
    ['issuer', 'https://other-issuer.example.test'],
    ['connection_id', 'other-connection'],
    ['organization_id', 'other-organization'],
    ['installation_id', 'other-installation'],
    ['authority_generation', 8],
]);

it('treats every callback correlation refusal as one response without exchange', function (string $case): void {
    ['baseUrl' => $baseUrl, 'secret' => $secret] = managedConnection();
    $fixture = managedFixture($baseUrl, $secret);
    $handoff = beginManagedHandoff($fixture);

    if ($case === 'expired') {
        DB::table('bfc_managed_handoffs')->update(['expires_at' => now()->subSecond()]);
    } elseif ($case === 'wrong-binding') {
        DB::table('bfc_managed_handoffs')->update(['connection_id' => 'tampered-connection']);
    } elseif ($case === 'wrong-generation') {
        DB::table('bfc_authority')->update(['generation' => 8]);
    } elseif ($case === 'replayed') {
        DB::table('bfc_managed_handoffs')->update(['consumed_at' => now()]);
    }

    $state = $case === 'unknown' ? str_repeat('A', 43) : $handoff['state'];
    $response = $this->withSession([ManagedHandoff::SESSION_NONCE_KEY => $handoff['nonce']])
        ->get('/bfc/managed/callback?'.http_build_query(['state' => $state, 'code' => 'valid-code']));

    $response->assertStatus(404)
        ->assertHeader('Content-Type', 'text/plain; charset=UTF-8')
        ->assertSeeText('Not Found');
    expect($response->headers->has('Location'))->toBeFalse()
        ->and($fixture->calls)->toHaveCount(1);
})->with(['unknown', 'expired', 'wrong-binding', 'wrong-generation', 'replayed']);

it('derives both authority route sets structurally, pins their package gates, and catches an ungated positive control', function (): void {
    /** @var Router $router */
    $router = app('router');
    $derive = function () use ($router): array {
        $sets = ['standalone' => [], 'managed' => []];

        foreach ($router->getRoutes() as $route) {
            $action = $route->getActionName();
            $class = explode('@', $action, 2)[0];
            $short = strrchr($class, '\\') ?: $class;

            if (str_starts_with($short, '\\Standalone')) {
                $sets['standalone'][] = $route;
            } elseif ($class === ManagedAuthentication::class) {
                $sets['managed'][] = $route;
            }
        }

        return $sets;
    };
    $sets = $derive();

    expect($sets['standalone'])->not->toBeEmpty()
        ->and($sets['managed'])->toHaveCount(2);

    foreach ([
        'standalone' => EnsureStandaloneAuthority::class,
        'managed' => EnsureManagedAuthority::class,
    ] as $mode => $gate) {
        foreach ($sets[$mode] as $route) {
            expect($router->gatherRouteMiddleware($route))->toContain($gate);
        }
    }

    $router->get('/_bfc-managed-ungated-control', [ManagedAuthentication::class, 'create']);
    $unprotected = array_filter(
        $derive()['managed'],
        static fn (Route $route): bool => ! in_array(
            EnsureManagedAuthority::class,
            $router->gatherRouteMiddleware($route),
            true,
        ),
    );
    expect(array_values(array_map(static fn (Route $route): string => $route->uri(), $unprotected)))
        ->toBe(['_bfc-managed-ungated-control']);
});

it('enforces managed and standalone exclusivity in both directions over the derived route sets', function (): void {
    managedConnection();

    /** @var Router $router */
    $router = app('router');
    foreach ($router->getRoutes() as $route) {
        $class = explode('@', $route->getActionName(), 2)[0];
        $short = strrchr($class, '\\') ?: $class;

        if (str_starts_with($short, '\\Standalone')) {
            $method = in_array('GET', $route->methods(), true) ? 'GET' : $route->methods()[0];
            $this->call($method, '/'.$route->uri())->assertNotFound();
        }
    }

    DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
        'mode' => AuthorityMode::Standalone->value,
        'generation' => 8,
    ]);
    Http::preventStrayRequests();
    $this->get('/bfc/managed/login')->assertNotFound();
    $this->get('/bfc/managed/callback')->assertNotFound();
    Http::assertNothingSent();
});

it('keeps the fixture and client on distinct application keys', function (): void {
    $clientKey = base64_encode(random_bytes(32));
    $fixtureKey = base64_encode(random_bytes(32));
    config(['app.key' => 'base64:'.$clientKey]);

    expect($fixtureKey)->not->toBe($clientKey);
});
