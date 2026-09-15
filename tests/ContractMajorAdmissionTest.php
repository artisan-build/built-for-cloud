<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\BuiltForCloud;
use ArtisanBuild\BuiltForCloud\ClientIdentity;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\Http\Middleware\AuthenticateMcp;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureConsoleSession;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureContractMajor;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAbility;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureDashboardCredential;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureManagedAuthority;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureStandaloneAuthority;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAdmin;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAuthenticated;
use ArtisanBuild\BuiltForCloud\Http\Middleware\ExpireStandaloneHandoffOnRefusal;
use ArtisanBuild\BuiltForCloud\Http\Middleware\UniformConsoleKeyRefusal;
use ArtisanBuild\BuiltForCloud\Http\Middleware\VerifyHmacSignature;
use ArtisanBuild\BuiltForCloud\HttpContract;
use ArtisanBuild\BuiltForCloud\SubjectType;
use Illuminate\Contracts\Auth\Middleware\AuthenticatesRequests;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Foundation\Http\Kernel as HttpKernel;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Routing\Events\RouteMatched;
use Illuminate\Routing\Middleware\ThrottleRequests;
use Illuminate\Routing\Router;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use Symfony\Component\Process\Process;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    Route::post('/contract-major-probe', function (Request $request): array {
        Cache::put('contract-major-domain-ran', true);

        return [
            'credential_id' => $request->user()?->getAuthIdentifier(),
            'actor_credential_id' => $request->attributes->get('bfc.actor_credential_id'),
            'client_id' => $request->header(ClientIdentity::HEADER),
        ];
    })->middleware(['bfc.contract-major', 'bfc.mcp']);
});

function assertContractMajorRefusal(TestResponse $response, int $status, string $error): void
{
    $response->assertStatus($status)
        ->assertHeader('Cache-Control', 'no-store, private')
        ->assertHeaderMissing('Retry-After')
        ->assertExactJson([
            'error' => $error,
            'supported_contract_major' => BuiltForCloud::API_VERSION,
        ]);

    expect($response->getContent())->toBe(json_encode([
        'error' => $error,
        'supported_contract_major' => BuiltForCloud::API_VERSION,
    ]));
}

it('accepts the one supported canonical major and implements every refusal row', function (): void {
    $secret = 'contract-major-accepted-secret';
    $credential = Credential::factory()->create([
        'kind' => CredentialKind::Bearer,
        'purpose' => CredentialPurpose::Mcp,
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'contract-major-accepted-consumer',
        'secret_hash' => hash('sha256', $secret),
        'status' => CredentialStatus::Active,
    ]);

    $this->postJson('/contract-major-probe', [], [
        HttpContract::MAJOR_HEADER => (string) BuiltForCloud::API_VERSION,
        'Authorization' => 'Bearer '.$secret,
    ])->assertOk()->assertJsonPath('credential_id', $credential->id);

    assertContractMajorRefusal($this->postJson('/contract-major-probe'), 400, 'missing_contract_major');
    assertContractMajorRefusal(
        $this->withHeader(HttpContract::MAJOR_HEADER, '02')->postJson('/contract-major-probe'),
        400,
        'malformed_contract_major',
    );
    assertContractMajorRefusal(
        $this->withHeader(HttpContract::MAJOR_HEADER, '3')->postJson('/contract-major-probe'),
        426,
        'unsupported_contract_major',
    );
});

it('refuses every non-canonical syntax without reflection', function (string $value): void {
    $logged = [];
    Log::listen(function (MessageLogged $event) use (&$logged): void {
        $logged[] = $event->message.' '.json_encode($event->context);
    });

    $response = $this->withHeader(HttpContract::MAJOR_HEADER, $value)->postJson('/contract-major-probe');

    assertContractMajorRefusal($response, 400, 'malformed_contract_major');
    if (str_contains($value, 'marker')) {
        expect($response->getContent())->not->toContain($value)
            ->and(json_encode($response->headers->all()))->not->toContain($value)
            ->and(implode('\n', $logged))->not->toContain($value);
    }
})->with([
    'empty' => '',
    'plus sign' => '+2',
    'minus sign' => '-2',
    'leading whitespace' => ' 2',
    'trailing whitespace' => '2 ',
    'internal whitespace' => '2 0',
    'comma joined' => '2,2',
    'leading zero' => '02',
    'decimal point' => '2.0',
    'exponent' => '2e0',
    'letters' => 'major-two-marker',
]);

it('refuses duplicate header values delivered to the request header bag', function (): void {
    $request = Request::create('/contract-major-probe', 'POST', server: ['HTTP_ACCEPT' => 'application/json']);
    $request->headers->set(HttpContract::MAJOR_HEADER, ['2', '2']);

    $response = new TestResponse(app(Kernel::class)->handle($request));

    assertContractMajorRefusal($response, 400, 'malformed_contract_major');
});

it('ignores every alternate value channel', function (array $parameters, array $headers): void {
    assertContractMajorRefusal(
        $this->postJson('/contract-major-probe?BFC-Contract-Version=2', $parameters, $headers),
        400,
        'missing_contract_major',
    );
})->with([
    'request body' => [['BFC-Contract-Version' => 2], []],
    'alternate header name' => [[], ['BFC-Contract-Major' => '2']],
]);

it('classifies every other canonical unsigned decimal as unsupported', function (string $value): void {
    assertContractMajorRefusal(
        $this->withHeader(HttpContract::MAJOR_HEADER, $value)->postJson('/contract-major-probe'),
        426,
        'unsupported_contract_major',
    );
})->with(['0', '1', '3', '999999999999999999999999999999999999']);

it('refuses before credential replay queue cache and domain work', function (): void {
    Queue::fake();
    $secret = 'contract-major-side-effect-secret';
    $credential = Credential::factory()->create([
        'kind' => CredentialKind::Bearer,
        'purpose' => CredentialPurpose::Mcp,
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'contract-major-side-effect-consumer',
        'secret_hash' => hash('sha256', $secret),
        'status' => CredentialStatus::Active,
    ]);

    assertContractMajorRefusal($this->postJson('/contract-major-probe', [], [
        HttpContract::MAJOR_HEADER => '02',
        'Authorization' => 'Bearer '.$secret,
        ClientIdentity::HEADER => 'side-effect-probe',
    ]), 400, 'malformed_contract_major');

    expect($credential->refresh()->last_used_at)->toBeNull()
        ->and(Cache::has('contract-major-domain-ran'))->toBeFalse();
    Queue::assertNothingPushed();
});

it('does not derive authority from the major or advisory client identity', function (): void {
    foreach (['2', '3'] as $major) {
        $response = $this->postJson('/contract-major-probe', [], [
            HttpContract::MAJOR_HEADER => $major,
            'Authorization' => 'Bearer unknown-contract-major-credential',
            ClientIdentity::HEADER => 'claimed-authority',
        ]);

        $response->assertStatus($major === '2' ? 401 : 426);
    }

    expect(Cache::has('contract-major-domain-ran'))->toBeFalse();
});

it('registers the exact alias and resolves admission before every package authentication middleware', function (): void {
    /** @var Router $router */
    $router = app('router');
    app(Kernel::class);

    expect($router->getMiddleware()['bfc.contract-major'] ?? null)->toBe(EnsureContractMajor::class);

    $authentication = [
        EnsureManagedAuthority::class,
        EnsureStandaloneAuthority::class,
        EnsureConsoleSession::class,
        AuthenticateMcp::class,
        VerifyHmacSignature::class,
        EnsureDashboardCredential::class,
        EnsureCredentialAdmin::class,
        EnsureCredentialAbility::class,
        EnsureUserIsAuthenticated::class,
        EnsureUserIsAdmin::class,
    ];
    $declaredAuthentication = array_reverse($authentication);
    $existing = [
        ThrottleRequests::class,
        UniformConsoleKeyRefusal::class,
        ...$declaredAuthentication,
        StartSession::class,
        ExpireStandaloneHandoffOnRefusal::class,
    ];
    $baseline = $router->resolveMiddleware($existing);
    $route = Route::get('/contract-major-order-probe', fn (): array => ['ok' => true])
        ->middleware([...$existing, 'bfc.contract-major']);
    Event::dispatch(new RouteMatched($route, Request::create('/contract-major-order-probe')));
    $resolved = $router->gatherRouteMiddleware($route);
    $admission = array_search(EnsureContractMajor::class, $resolved, true);

    expect($admission)->toBeInt();

    foreach ($authentication as $middleware) {
        expect(array_search($middleware, $resolved, true), $middleware)->toBeGreaterThan($admission);
    }

    expect(array_values(array_filter(
        $resolved,
        static fn (string $middleware): bool => $middleware !== EnsureContractMajor::class,
    )))->toBe($baseline)
        ->and(array_values(array_intersect($resolved, $authentication)))->toBe($declaredAuthentication);
});

it('reorders a parameterized contract-major alias without dropping its parameters', function (): void {
    /** @var Router $router */
    $router = app('router');
    $route = Route::get('/contract-major-parameterized-order-probe', fn (): array => ['ok' => true])
        ->middleware(['bfc.mcp', 'bfc.contract-major:product']);

    Event::dispatch(new RouteMatched($route, Request::create('/contract-major-parameterized-order-probe')));

    expect($router->gatherRouteMiddleware($route))->toBe([
        EnsureContractMajor::class.':product',
        AuthenticateMcp::class,
    ]);
});

it('reorders parameterized admission past non-string resolved middleware', function (): void {
    /** @var Router $router */
    $router = app('router');
    $inline = static fn (Request $request, Closure $next): mixed => $next($request);
    $router->aliasMiddleware('contract-major-inline-probe', $inline);
    $route = Route::get('/contract-major-inline-order-probe', fn (): array => ['ok' => true])
        ->middleware(['contract-major-inline-probe', 'bfc.mcp', 'bfc.contract-major:product']);

    Event::dispatch(new RouteMatched($route, Request::create('/contract-major-inline-order-probe')));

    expect($router->gatherRouteMiddleware($route))->toBe([
        $inline,
        EnsureContractMajor::class.':product',
        AuthenticateMcp::class,
    ]);
});

it('leaves the global middleware priority byte-identical to the framework baseline', function (): void {
    $kernel = app(Kernel::class);

    expect($kernel)->toBeInstanceOf(HttpKernel::class);

    /** @var list<class-string> $baseline */
    $baseline = (new ReflectionClass($kernel))->getDefaultProperties()['middlewarePriority'];

    /** @var HttpKernel $kernel */
    expect($kernel->getMiddlewarePriority())->toBe($baseline)
        ->and($kernel->getMiddlewarePriority())->not->toContain(EnsureContractMajor::class);
});

it('refuses before every configured bfc guard spelling when authentication is declared first', function (
    string $suffix,
    string $authentication,
    array $configuration,
    array $headers,
    string $error,
): void {
    config($configuration);
    auth()->forgetGuards();

    $secret = 'contract-major-guard-order-'.$suffix.'-secret';
    $credential = Credential::factory()->create([
        'kind' => CredentialKind::Bearer,
        'purpose' => CredentialPurpose::Consumption,
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'contract-major-guard-order-'.$suffix,
        'secret_hash' => hash('sha256', $secret),
        'status' => CredentialStatus::Active,
    ]);
    $uri = '/contract-major-guard-order-'.$suffix;
    Route::post($uri, function (): array {
        Cache::put('contract-major-guard-domain-ran', true);

        return ['ok' => true];
    })->middleware([$authentication, 'bfc.contract-major']);

    $response = $this->postJson($uri, [], [
        ...$headers,
        'Authorization' => 'Bearer '.$secret,
    ]);

    assertContractMajorRefusal($response, 400, $error);

    /** @var Router $router */
    $router = app('router');
    $route = Route::getRoutes()->match(Request::create($uri, 'POST'));
    $resolved = $router->gatherRouteMiddleware($route);
    $admission = array_search(EnsureContractMajor::class, $resolved, true);
    $authenticationIndex = null;

    foreach ($resolved as $index => $middleware) {
        [$name] = explode(':', $middleware, 2);

        if (is_a($name, AuthenticatesRequests::class, true)) {
            $authenticationIndex = $index;
            break;
        }
    }

    expect($admission)->toBeInt()
        ->and($authenticationIndex)->toBeInt()
        ->and($admission)->toBeLessThan($authenticationIndex)
        ->and($credential->refresh()->last_used_at)->toBeNull()
        ->and(Cache::has('contract-major-guard-domain-ran'))->toBeFalse();
})->with([
    'auth:bfc missing' => [
        'explicit-missing',
        'auth:bfc',
        ['auth.guards.bfc' => ['driver' => 'bfc', 'provider' => null]],
        [],
        'missing_contract_major',
    ],
    'auth:bfc malformed' => [
        'explicit-malformed',
        'auth:bfc',
        ['auth.guards.bfc' => ['driver' => 'bfc', 'provider' => null]],
        [HttpContract::MAJOR_HEADER => '02'],
        'malformed_contract_major',
    ],
    'renamed guard missing' => [
        'renamed-missing',
        'auth:contract-api',
        ['auth.guards.contract-api' => ['driver' => 'bfc', 'provider' => null]],
        [],
        'missing_contract_major',
    ],
    'renamed guard malformed' => [
        'renamed-malformed',
        'auth:contract-api',
        ['auth.guards.contract-api' => ['driver' => 'bfc', 'provider' => null]],
        [HttpContract::MAJOR_HEADER => '02'],
        'malformed_contract_major',
    ],
    'default guard missing' => [
        'default-missing',
        'auth',
        [
            'auth.defaults.guard' => 'contract-default',
            'auth.guards.contract-default' => ['driver' => 'bfc', 'provider' => null],
        ],
        [],
        'missing_contract_major',
    ],
    'default guard malformed' => [
        'default-malformed',
        'auth',
        [
            'auth.defaults.guard' => 'contract-default',
            'auth.guards.contract-default' => ['driver' => 'bfc', 'provider' => null],
        ],
        [HttpContract::MAJOR_HEADER => '02'],
        'malformed_contract_major',
    ],
]);

it('does not reorder unrelated Laravel authentication guards', function (): void {
    config([
        'auth.defaults.guard' => 'web',
        'auth.guards.web' => ['driver' => 'session', 'provider' => null],
    ]);

    /** @var Router $router */
    $router = app('router');
    $route = Route::get('/contract-major-foreign-guard-order', fn (): array => ['ok' => true])
        ->middleware(['auth:web', 'bfc.contract-major']);
    $baseline = $router->resolveMiddleware($route->gatherMiddleware(), $route->excludedMiddleware());

    Event::dispatch(new RouteMatched($route, Request::create('/contract-major-foreign-guard-order')));

    expect($router->gatherRouteMiddleware($route))->toBe($baseline);
});

it('reorders configured bfc guards from a real compiled route collection', function (): void {
    $payload = sys_get_temp_dir().'/bfc-contract-major-route-cache-'.bin2hex(random_bytes(8)).'.php';

    try {
        $generate = new Process([PHP_BINARY, __DIR__.'/Fixtures/contract-major-route-cache.php', 'generate', $payload]);
        $generate->setTimeout(60);
        $generate->mustRun();

        expect($generate->getOutput())->toContain('"contains":true');

        $load = new Process([PHP_BINARY, __DIR__.'/Fixtures/contract-major-route-cache.php', 'load', $payload]);
        $load->setTimeout(60);
        $load->run();

        expect($load->getExitCode())->toBe(0, $load->getOutput().$load->getErrorOutput())
            ->and($load->getOutput())->toContain('contract-major-route-cache-ok');
    } finally {
        @unlink($payload);
    }
});

it('keeps all existing package routes outside opt-in admission', function (): void {
    /** @var Router $router */
    $router = app('router');

    $packageRoutes = array_filter(
        Route::getRoutes()->getRoutes(),
        static fn ($route): bool => str_starts_with($route->getActionName(), 'ArtisanBuild\\BuiltForCloud\\'),
    );

    expect($packageRoutes)->not->toBe([]);

    foreach ($packageRoutes as $route) {
        expect($router->resolveMiddleware($route->middleware(), $route->excludedMiddleware()))
            ->not->toContain(EnsureContractMajor::class);
    }

    $this->getJson('/bfc/meta')->assertOk();
});

it('pins the shared header server major docs and closed error vocabulary', function (): void {
    $docs = file_get_contents(dirname(__DIR__).'/docs/http-contract.md');

    expect(HttpContract::MAJOR_HEADER)->toBe('BFC-Contract-Version')
        ->and(BuiltForCloud::API_VERSION)->toBe(2)
        ->and($docs)->toContain('`bfc.contract-major`')
        ->and($docs)->toContain(HttpContract::MAJOR_HEADER)
        ->and($docs)->toContain('missing_contract_major')
        ->and($docs)->toContain('malformed_contract_major')
        ->and($docs)->toContain('unsupported_contract_major');
});
