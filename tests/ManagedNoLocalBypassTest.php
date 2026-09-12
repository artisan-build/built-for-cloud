<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureStandaloneAuthority;
use ArtisanBuild\BuiltForCloud\Tests\Support\StandaloneSurfaceInventory;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Route as RouteFacade;

require_once __DIR__.'/Fixtures/FutureLocalAuthenticationController.php';

trait EnablesEveryPackageRoute
{
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('built-for-cloud.surfaces.routes', true);
        $app['config']->set('built-for-cloud.console.enabled', true);
        $app['config']->set('built-for-cloud.credential_api.enabled', true);
    }
}

uses(EnablesEveryPackageRoute::class);

it('derives the standalone surface structurally and detects an added route without its authority gate', function (): void {
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

    $controlController = 'ArtisanBuild\\BuiltForCloud\\Http\\Controllers\\FutureLocalAuthenticationController';
    $control = RouteFacade::get('/_bfc-standalone-inventory-control', [$controlController, 'authenticate']);
    $discoveredControl = array_values(array_filter(
        StandaloneSurfaceInventory::packageRoutes($router),
        static fn (Route $route): bool => $route === $control,
    ));
    $unexpectedControllers = array_values(array_diff(
        array_unique(array_map(StandaloneSurfaceInventory::controller(...), StandaloneSurfaceInventory::packageRoutes($router))),
        $expectedControllers,
    ));

    expect($discoveredControl)->toHaveCount(1)
        ->and($unexpectedControllers)->toBe([$controlController])
        ->and($router->gatherRouteMiddleware($discoveredControl[0]))
        ->not->toContain(EnsureStandaloneAuthority::class);
});
