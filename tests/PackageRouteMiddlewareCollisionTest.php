<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ClientObservations;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ConsoleChromeScript;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ConsoleVitals;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageConsoleKeys;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageCredentials;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageOnboarding;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageOwnership;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageSubjects;
use ArtisanBuild\BuiltForCloud\Http\Controllers\OperatorRouteController;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureConsoleSession;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureDashboardCredential;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\Ownership;
use ArtisanBuild\BuiltForCloud\StandaloneRouteOwnership;
use ArtisanBuild\BuiltForCloud\SubjectType;
use Closure;
use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Routing\CompiledRouteCollection;
use Illuminate\Routing\Events\RouteMatched;
use Illuminate\Routing\Events\Routing;
use Illuminate\Routing\Route;
use Illuminate\Routing\RouteCollection;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Notification;
use ReflectionProperty;
use RuntimeException;
use Symfony\Component\HttpFoundation\Response;

uses(RefreshDatabase::class);

final class HostilePackageGateMiddleware
{
    /** @var list<string> */
    public static array $paths = [];

    public function handle(Request $request, Closure $next): Response
    {
        self::$paths[] = $request->path();

        return $next($request);
    }
}

final class UninventoriedOperatorController extends OperatorRouteController
{
    public function __invoke(): Response
    {
        return new Response('should not run', 201);
    }
}

final class RequestSwappingPackageGateMiddleware
{
    /** @param Closure(Request): Response $next */
    public function handle(Request $request, Closure $next): Response
    {
        app()->instance('request', Request::create('/_bfc-test/routeless-container-request', 'POST'));

        return $next($request);
    }
}

beforeEach(function (): void {
    /** @var Router $router */
    $router = app('router');

    // Materialize the kernel's aliases before the hostile host replaces
    // every package alias with both forms Laravel can resolve first.
    app(Kernel::class);

    $packageAliases = array_keys(array_filter(
        $router->getMiddleware(),
        static fn (mixed $middleware): bool => is_string($middleware)
            && str_starts_with($middleware, 'ArtisanBuild\\BuiltForCloud\\Http\\Middleware\\'),
    ));

    expect($packageAliases)->not->toBe([]);

    foreach ($packageAliases as $alias) {
        $router->aliasMiddleware($alias, HostilePackageGateMiddleware::class);
        $router->middlewareGroup($alias, [HostilePackageGateMiddleware::class]);
    }

    HostilePackageGateMiddleware::$paths = [];
});

function collisionOwnership(?string $bearer = null): Ownership
{
    $owner = Credential::factory()->create([
        'subject_type' => SubjectType::Operator,
        'subject_ref' => 'collision-owner',
        'abilities' => [EnsureCredentialAdmin::ABILITY],
        ...($bearer === null ? [] : ['secret_hash' => hash('sha256', $bearer)]),
    ]);

    return Ownership::query()->create(['owner_credential_id' => $owner->getKey()]);
}

/** @return array<string, array{uri: string, methods: list<string>, action: string, gate: string}> */
function packageOperatorGateInventory(): array
{
    return [
        'POST /bfc/ownership/release' => ['uri' => 'bfc/ownership/release', 'methods' => ['POST'], 'action' => ManageOwnership::class.'@release', 'gate' => EnsureCredentialAdmin::class.':'.OperatorAbility::OwnershipRelease->value],
        'POST /bfc/ownership/cancel-transfer' => ['uri' => 'bfc/ownership/cancel-transfer', 'methods' => ['POST'], 'action' => ManageOwnership::class.'@cancelTransfer', 'gate' => EnsureCredentialAdmin::class.':'.OperatorAbility::OwnershipRelease->value],
        'POST /bfc/onboarding/issue' => ['uri' => 'bfc/onboarding/issue', 'methods' => ['POST'], 'action' => ManageOnboarding::class.'@issue', 'gate' => EnsureCredentialAdmin::class.':'.OperatorAbility::CredentialMint->value],
        'GET /bfc/credentials' => ['uri' => 'bfc/credentials', 'methods' => ['GET', 'HEAD'], 'action' => ManageCredentials::class.'@index', 'gate' => EnsureCredentialAdmin::class.':'.OperatorAbility::CredentialRead->value],
        'POST /bfc/credentials' => ['uri' => 'bfc/credentials', 'methods' => ['POST'], 'action' => ManageCredentials::class.'@store', 'gate' => EnsureCredentialAdmin::class.':'.OperatorAbility::CredentialMint->value],
        'DELETE /bfc/credentials/{id}' => ['uri' => 'bfc/credentials/{id}', 'methods' => ['DELETE'], 'action' => ManageCredentials::class.'@destroy', 'gate' => EnsureCredentialAdmin::class.':'.OperatorAbility::CredentialRevoke->value],
        'POST /bfc/credentials/{id}/rotate' => ['uri' => 'bfc/credentials/{id}/rotate', 'methods' => ['POST'], 'action' => ManageCredentials::class.'@rotate', 'gate' => EnsureCredentialAdmin::class.':'.OperatorAbility::CredentialRotate->value],
        'POST /bfc/credentials/{id}/activate' => ['uri' => 'bfc/credentials/{id}/activate', 'methods' => ['POST'], 'action' => ManageCredentials::class.'@activate', 'gate' => EnsureCredentialAdmin::class.':'.OperatorAbility::CredentialRotate->value],
        'POST /bfc/console/re-key' => ['uri' => 'bfc/console/re-key', 'methods' => ['POST'], 'action' => ManageConsoleKeys::class.'@reKey', 'gate' => EnsureCredentialAdmin::class.':'.OperatorAbility::ConsoleKeyWrite->value],
        'POST /bfc/console/keys/{key_id}/retire' => ['uri' => 'bfc/console/keys/{key_id}/retire', 'methods' => ['POST'], 'action' => ManageConsoleKeys::class.'@retire', 'gate' => EnsureCredentialAdmin::class.':'.OperatorAbility::ConsoleKeyWrite->value],
        'GET /bfc/console/vitals' => ['uri' => 'bfc/console/vitals', 'methods' => ['GET', 'HEAD'], 'action' => ConsoleVitals::class, 'gate' => EnsureDashboardCredential::class],
        'GET /bfc/console/chrome.js' => ['uri' => 'bfc/console/chrome.js', 'methods' => ['GET', 'HEAD'], 'action' => ConsoleChromeScript::class, 'gate' => EnsureConsoleSession::class],
        'POST /bfc/subjects/offboard' => ['uri' => 'bfc/subjects/offboard', 'methods' => ['POST'], 'action' => ManageSubjects::class.'@offboard', 'gate' => EnsureCredentialAdmin::class.':'.OperatorAbility::SubjectOffboard->value],
        'GET /bfc/client-observations' => ['uri' => 'bfc/client-observations', 'methods' => ['GET', 'HEAD'], 'action' => ClientObservations::class, 'gate' => EnsureCredentialAdmin::class.':'.OperatorAbility::CredentialRead->value],
    ];
}

/**
 * @param  array<string, array{uri: string, methods: list<string>, action: string, gate: string}>  $inventory
 * @return array{checked: array<string, string>, breaks: list<string>, routes: list<array{route: Route, gate: string}>}
 */
function packageGateProtectionScan(Router $router, array $inventory): array
{
    $checked = [];
    $breaks = [];
    $ownedRoutes = [];
    $routes = $router->getRoutes()->getRoutes();

    foreach ($inventory as $label => $expected) {
        $checked[$label] = $expected['gate'];
        $matches = array_values(array_filter($routes, static fn (Route $route): bool => $route->getDomain() === null
            && $route->uri() === $expected['uri']
            && array_diff($route->methods(), $expected['methods']) === []
            && array_diff($expected['methods'], $route->methods()) === []));

        if (count($matches) !== 1) {
            $breaks[] = $label.': expected one structurally matching route, found '.count($matches);

            continue;
        }

        $route = $matches[0];
        $ownedRoutes[] = ['route' => $route, 'gate' => $expected['gate']];

        if ($route->getActionName() !== $expected['action']) {
            $breaks[] = $label.': expected action '.$expected['action'].', found '.$route->getActionName();
        }

        $resolved = $router->resolveMiddleware($route->middleware(), $route->excludedMiddleware());

        if (! in_array($expected['gate'], $resolved, true)) {
            $breaks[] = $label.': missing '.$expected['gate'];
        }
    }

    ksort($checked);
    sort($breaks);

    return ['checked' => $checked, 'breaks' => $breaks, 'routes' => $ownedRoutes];
}

/** @param list<array{route: Route, gate: string}> $ownedRoutes */
function applyOperatorGateAttack(Router $router, array $ownedRoutes, string $vector): void
{
    $restoreAliases = static function () use ($router): void {
        $router->aliasMiddleware('bfc.credential.admin', EnsureCredentialAdmin::class);
        $router->aliasMiddleware('bfc.console', EnsureConsoleSession::class);
        $router->middlewareGroup('bfc.credential.admin', [EnsureCredentialAdmin::class]);
        $router->middlewareGroup('bfc.console', [EnsureConsoleSession::class]);

        foreach ([EnsureCredentialAdmin::class, EnsureConsoleSession::class, EnsureDashboardCredential::class] as $gate) {
            $router->aliasMiddleware($gate, $gate);
        }

        $router->aliasMiddleware('auth', Authenticate::class);
    };

    if ($vector === 'package-alias') {
        return;
    }

    if ($vector === 'fqcn-alias') {
        foreach ([EnsureCredentialAdmin::class, EnsureConsoleSession::class, EnsureDashboardCredential::class] as $gate) {
            $router->aliasMiddleware($gate, HostilePackageGateMiddleware::class);
        }

        return;
    }

    if ($vector === 'fqcn-group') {
        foreach ([EnsureCredentialAdmin::class, EnsureConsoleSession::class, EnsureDashboardCredential::class] as $gate) {
            $router->middlewareGroup($gate, [HostilePackageGateMiddleware::class]);
        }

        return;
    }

    if ($vector === 'parameterized-group') {
        foreach ($ownedRoutes as ['gate' => $gate]) {
            if (str_starts_with($gate, EnsureCredentialAdmin::class.':')) {
                $router->middlewareGroup($gate, [HostilePackageGateMiddleware::class]);
            }
        }

        return;
    }

    if ($vector === 'alias-exclusion') {
        $restoreAliases();

        foreach ($ownedRoutes as ['route' => $route, 'gate' => $gate]) {
            $alias = match (true) {
                $gate === EnsureConsoleSession::class => 'bfc.console',
                str_starts_with($gate, EnsureCredentialAdmin::class.':') => 'bfc.credential.admin:'.explode(':', $gate, 2)[1],
                default => null,
            };

            if ($alias !== null) {
                $route->withoutMiddleware($alias);
            }
        }

        return;
    }

    if ($vector === 'fqcn-exclusion') {
        foreach ($ownedRoutes as ['route' => $route, 'gate' => $gate]) {
            $route->withoutMiddleware($gate);
        }

        return;
    }

    if ($vector === 'later-wildcard-alias') {
        Event::listen(Routing::class, $restoreAliases);
        Event::listen(RouteMatched::class.'*', static function () use ($router): void {
            foreach ([EnsureCredentialAdmin::class, EnsureConsoleSession::class, EnsureDashboardCredential::class] as $gate) {
                $router->aliasMiddleware($gate, HostilePackageGateMiddleware::class);
            }

            $router->aliasMiddleware('auth', HostilePackageGateMiddleware::class);
        });

        return;
    }

    throw new RuntimeException('Unknown operator gate attack vector: '.$vector);
}

it('keeps every inventoried operator gate effective through package-alias collisions', function (): void {
    /** @var Router $router */
    $router = app('router');
    $inventory = packageOperatorGateInventory();
    $scan = packageGateProtectionScan($router, $inventory);
    $expectedLabels = array_keys($inventory);
    sort($expectedLabels);

    expect(array_keys($scan['checked']))->toBe($expectedLabels)
        ->and(array_values(array_unique($scan['checked'])))->toContain(
            EnsureConsoleSession::class,
            EnsureCredentialAdmin::class.':credential:read',
            EnsureDashboardCredential::class,
        )
        ->and($scan['breaks'])->toBe([]);

    foreach ($inventory as $expected) {
        expect(StandaloneRouteOwnership::operatorGateForAction($expected['action']))->toBe($expected['gate']);
    }
});

it('fails closed when an operator controller action is absent from the inventory', function (): void {
    /** @var Router $router */
    $router = app('router');
    $router->get('/_bfc-test/uninventoried-operator', UninventoriedOperatorController::class);
    $this->withoutExceptionHandling();

    expect(fn () => $this->get('/_bfc-test/uninventoried-operator'))
        ->toThrow(RuntimeException::class, 'is missing from the operator route inventory');
});

it('keeps the public ownership claim action explicitly free of an operator gate', function (): void {
    expect(StandaloneRouteOwnership::operatorGateForAction(ManageOwnership::class.'@claim'))->toBeNull();
});

it('derives the required gate from the executing action when setAction diverges from uses', function (): void {
    /** @var Router $router */
    $router = app('router');
    $route = $router->post('/_bfc-test/action-divergence', [ManageOwnership::class, 'release']);
    $action = $route->getAction();
    $action['controller'] = ManageOwnership::class.'@claim';
    $route->setAction($action);

    expect($route->getAction('uses'))->toBe(ManageOwnership::class.'@release')
        ->and($route->getActionName())->toBe(ManageOwnership::class.'@claim');

    $ownership = collisionOwnership();
    $this->withoutExceptionHandling();

    expect(fn () => $this->post('/_bfc-test/action-divergence'))
        ->toThrow(RuntimeException::class, 'did not execute its built-for-cloud operator gate');
    expect($ownership->refresh()->pending_claim_id)->toBeNull();
});

it('derives the required gate from the executing action after compiled route reconstruction', function (): void {
    /** @var Router $router */
    $router = app('router');
    $routes = new RouteCollection;
    $routes->add($router->newRoute(['POST'], '_bfc-test/compiled-action-divergence', [
        'uses' => ManageOwnership::class.'@release',
        'controller' => ManageOwnership::class.'@claim',
    ]));
    $router->setCompiledRoutes($routes->compile());

    expect($router->getRoutes())->toBeInstanceOf(CompiledRouteCollection::class);

    $ownership = collisionOwnership();
    $this->withoutExceptionHandling();

    expect(fn () => $this->post('/_bfc-test/compiled-action-divergence'))
        ->toThrow(RuntimeException::class, 'did not execute its built-for-cloud operator gate');
    expect($ownership->refresh()->pending_claim_id)->toBeNull();
});

it('fails closed when a matched request loses its route resolver before controller dispatch', function (): void {
    Event::listen(RouteMatched::class.'*', static function (string $event, array $payload): void {
        $matched = $payload[0] ?? null;

        if ($event === RouteMatched::class && $matched instanceof RouteMatched) {
            $matched->request->setRouteResolver(static fn (): null => null);
        }
    });

    $bearer = 'routeless-resolver-fixture';
    $ownership = collisionOwnership($bearer);
    $this->withoutExceptionHandling();

    expect(fn () => $this->withHeader('Authorization', 'Bearer '.$bearer)->post('/bfc/ownership/release'))
        ->toThrow(RuntimeException::class, 'has no resolved route');
    expect($ownership->refresh()->pending_claim_id)->toBeNull();
});

it('fails closed when a rebound gate swaps the container request for a routeless request', function (): void {
    app()->bind(EnsureCredentialAdmin::class, RequestSwappingPackageGateMiddleware::class);

    $ownership = collisionOwnership();
    $this->withoutExceptionHandling();

    expect(fn () => $this->post('/bfc/ownership/release'))
        ->toThrow(RuntimeException::class, 'has no resolved route');
    expect($ownership->refresh()->pending_claim_id)->toBeNull();
});

it('reports an explicitly inventoried route whose gate is missing entirely', function (): void {
    /** @var Router $router */
    $router = app('router');
    $router->post('/bfc/ownership/release', [ManageOwnership::class, 'release']);
    $scan = packageGateProtectionScan($router, packageOperatorGateInventory());

    expect($scan['breaks'])->toContain(
        'POST /bfc/ownership/release: missing '.EnsureCredentialAdmin::class.':'.OperatorAbility::OwnershipRelease->value,
    );

    $ownership = collisionOwnership();
    $this->withoutExceptionHandling();

    expect(fn () => $this->post('/bfc/ownership/release'))
        ->toThrow(RuntimeException::class, 'must retain its built-for-cloud operator gate');
    expect($ownership->refresh()->pending_claim_id)->toBeNull();
});

it('asserts the operator inventory without populating the route middleware cache', function (): void {
    /** @var Router $router */
    $router = app('router');
    $scan = packageGateProtectionScan($router, packageOperatorGateInventory());
    $computed = new ReflectionProperty(Route::class, 'computedMiddleware');
    $computed->setAccessible(true);

    foreach ($scan['routes'] as ['route' => $route]) {
        expect($computed->getValue($route))->toBeNull();
    }

    StandaloneRouteOwnership::assertOperatorOwned($router, $scan['routes']);

    foreach ($scan['routes'] as ['route' => $route]) {
        expect($computed->getValue($route))->toBeNull();
    }

    $router->aliasMiddleware(EnsureCredentialAdmin::class, HostilePackageGateMiddleware::class);

    expect(fn () => StandaloneRouteOwnership::assertOperatorOwned($router, $scan['routes']))
        ->toThrow(RuntimeException::class, 'must retain its built-for-cloud operator gate');

    foreach ($scan['routes'] as ['route' => $route]) {
        expect($computed->getValue($route))->toBeNull();
    }
});

it('refuses every credential-admin and console-session route before domain effects across middleware resolution attacks', function (string $vector): void {
    Mail::fake();
    Notification::fake();

    /** @var Router $router */
    $router = app('router');
    $inventory = packageOperatorGateInventory();
    $scan = packageGateProtectionScan($router, $inventory);
    $routesToDrive = array_filter(
        $inventory,
        static fn (array $expected): bool => $expected['gate'] !== EnsureDashboardCredential::class,
    );

    expect($scan['breaks'])->toBe([])
        ->and($scan['routes'])->toHaveCount(count($inventory));

    applyOperatorGateAttack($router, $scan['routes'], $vector);

    $ownership = collisionOwnership();
    $credentialCount = Credential::query()->count();

    $tripwireRefusals = 0;

    if ($vector === 'later-wildcard-alias') {
        $this->withoutExceptionHandling();
    }

    foreach (array_values($routesToDrive) as $index => $expected) {
        $path = '/'.preg_replace('/\{[^}]+\}/', 'missing', $expected['uri']);

        try {
            $response = $this->call(
                $expected['methods'][0],
                $path,
                server: ['REMOTE_ADDR' => '192.0.2.'.($index + 1)],
            );
        } catch (RuntimeException $exception) {
            expect($exception->getMessage())->toContain('did not execute its built-for-cloud operator gate');
            $tripwireRefusals++;

            continue;
        }

        expect($response->getStatusCode(), $expected['methods'][0].' '.$path)->toBeGreaterThanOrEqual(400);
    }

    expect($ownership->refresh()->pending_claim_id)->toBeNull()
        ->and(Credential::query()->count())->toBe($credentialCount);

    if ($vector === 'later-wildcard-alias') {
        expect($tripwireRefusals)->toBe(count($routesToDrive))
            ->and(HostilePackageGateMiddleware::$paths)->toHaveCount(count($routesToDrive) + 1);
    }

    Mail::assertNothingSent();
    Notification::assertNothingSent();
})->with([
    'package alias collision' => 'package-alias',
    'FQCN alias' => 'fqcn-alias',
    'FQCN group' => 'fqcn-group',
    'exact parameterized group' => 'parameterized-group',
    'alias-spelled exclusion' => 'alias-exclusion',
    'FQCN-spelled exclusion' => 'fqcn-exclusion',
    'later wildcard RouteMatched alias' => 'later-wildcard-alias',
]);

it('refuses console vitals without disclosing its body across dashboard gate collisions', function (string $vector): void {
    /** @var Router $router */
    $router = app('router');
    $scan = packageGateProtectionScan($router, packageOperatorGateInventory());
    applyOperatorGateAttack($router, $scan['routes'], $vector);
    $this->withoutExceptionHandling();

    $message = $vector === 'later-wildcard-alias'
        ? 'did not execute its built-for-cloud operator gate'
        : 'must retain its built-for-cloud operator gate';

    expect(fn () => $this->get('/bfc/console/vitals'))
        ->toThrow(RuntimeException::class, $message);
    expect(HostilePackageGateMiddleware::$paths)->toBe(
        $vector === 'later-wildcard-alias' ? ['bfc/console/vitals'] : [],
    );
})->with([
    'dashboard FQCN alias' => 'fqcn-alias',
    'dashboard FQCN group' => 'fqcn-group',
    'dashboard FQCN exclusion' => 'fqcn-exclusion',
    'dashboard later wildcard alias' => 'later-wildcard-alias',
]);

it('uses executed gate state to stop a mutation ordered after the resolved-stack assertion', function (): void {
    /** @var Router $router */
    $router = app('router');
    $scan = packageGateProtectionScan($router, packageOperatorGateInventory());
    applyOperatorGateAttack($router, $scan['routes'], 'later-wildcard-alias');

    $ownership = collisionOwnership();
    $this->withoutExceptionHandling();

    expect(fn () => $this->post('/bfc/ownership/release'))
        ->toThrow(RuntimeException::class, 'did not execute its built-for-cloud operator gate');
    expect(HostilePackageGateMiddleware::$paths)->toBe(['bfc/ownership/release'])
        ->and($ownership->refresh()->pending_claim_id)->toBeNull();
});

it('refuses one route from each gate family before controller effects under the hostile host', function (): void {
    Mail::fake();
    Notification::fake();

    $ownership = collisionOwnership();

    $this->postJson('/bfc/ownership/release')->assertUnauthorized();
    $this->postJson('/bfc/credentials', [
        'subject_type' => 'external_consumer',
        'subject_ref' => 'collision-target',
        'name' => 'collision-mint',
    ])->assertUnauthorized();
    $this->get('/bfc/console/chrome.js')
        ->assertUnauthorized()
        ->assertHeader('BFC-Console-Reentry', '1')
        ->assertJsonPath('error', 'console_reentry_required');

    expect($ownership->refresh()->pending_claim_id)->toBeNull()
        ->and(Credential::query()->where('name', 'collision-mint')->doesntExist())->toBeTrue()
        ->and(HostilePackageGateMiddleware::$paths)->toBe([]);

    Mail::assertNothingSent();
    Notification::assertNothingSent();
});
