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
use Illuminate\Contracts\Http\Kernel;
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
