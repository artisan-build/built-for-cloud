<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Http\Controllers\StandaloneAuthentication;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureStandaloneAuthority;
use ArtisanBuild\BuiltForCloud\Tests\Support\StandaloneSurfaceInventory;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Route as RouteFacade;

it('derives the standalone surface structurally and detects an added route without its authority gate', function (): void {
    /** @var Router $router */
    $router = app('router');
    $routes = StandaloneSurfaceInventory::routes($router);
    $controllers = array_values(array_unique(array_map(
        StandaloneSurfaceInventory::controller(...),
        $routes,
    )));

    expect($routes)->not->toBeEmpty();

    foreach (StandaloneSurfaceInventory::requiredControllerFamilies() as $controller) {
        expect($controllers)->toContain($controller);
    }

    foreach ($routes as $route) {
        expect($router->gatherRouteMiddleware($route))->toContain(EnsureStandaloneAuthority::class);
    }

    $control = RouteFacade::get('/_bfc-standalone-inventory-control', [StandaloneAuthentication::class, 'create']);
    $discoveredControl = array_values(array_filter(
        StandaloneSurfaceInventory::routes($router),
        static fn (Route $route): bool => $route === $control,
    ));

    expect($discoveredControl)->toHaveCount(1)
        ->and($router->gatherRouteMiddleware($discoveredControl[0]))
        ->not->toContain(EnsureStandaloneAuthority::class);
});
