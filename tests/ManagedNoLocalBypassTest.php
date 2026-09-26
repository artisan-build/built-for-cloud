<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureStandaloneAuthority;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\FutureLocalAuthenticationController;
use ArtisanBuild\BuiltForCloud\Tests\Support\StandaloneSurfaceInventory;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Route as RouteFacade;

require_once __DIR__.'/Fixtures/FutureLocalAuthenticationController.php';

it('derives the standalone surface structurally and detects closure and foreign-controller routes without their authority gate', function (): void {
    /** @var Router $router */
    $router = app('router');
    $packageRoutes = StandaloneSurfaceInventory::packageRoutes($router);
    $controllers = array_values(array_unique(array_map(
        StandaloneSurfaceInventory::controller(...),
        $packageRoutes,
    )));
    $expectedControllers = array_keys(StandaloneSurfaceInventory::expectedControllerFamilies());
    sort($controllers);
    sort($expectedControllers);
    $routes = StandaloneSurfaceInventory::routes($router);

    expect($routes)->not->toBeEmpty()
        ->and($controllers)->toBe($expectedControllers);

    foreach ($routes as $route) {
        expect($router->gatherRouteMiddleware($route))->toContain(EnsureStandaloneAuthority::class);
    }

    $closureControl = RouteFacade::get('/bfc/members/closure-control', static fn (): string => 'closure-control');
    $namespaceControl = RouteFacade::get(
        '/bfc/me/sessions/namespace-control',
        [FutureLocalAuthenticationController::class, 'authenticate'],
    );
    $controls = [$closureControl, $namespaceControl];
    $discoveredControls = array_values(array_filter(
        StandaloneSurfaceInventory::routes($router),
        static fn (Route $route): bool => in_array($route, $controls, true),
    ));
    $violations = array_values(array_map(
        static fn (Route $route): string => $route->uri(),
        array_filter(
            StandaloneSurfaceInventory::routes($router),
            static fn (Route $route): bool => ! in_array(
                EnsureStandaloneAuthority::class,
                $router->gatherRouteMiddleware($route),
                true,
            ),
        ),
    ));

    expect($discoveredControls)->toBe([$namespaceControl, $closureControl])
        ->and($violations)->toBe([
            'bfc/me/sessions/namespace-control',
            'bfc/members/closure-control',
        ]);
});
