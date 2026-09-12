<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureStandaloneAuthority;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\FutureLocalAuthenticationController;
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
    $expectedControllers = StandaloneSurfaceInventory::requiredControllerFamilies();
    sort($controllers);
    sort($expectedControllers);

    expect($routes)->not->toBeEmpty()
        ->and($controllers)->toBe($expectedControllers);

    foreach ($routes as $route) {
        expect($router->gatherRouteMiddleware($route))->toContain(EnsureStandaloneAuthority::class);
    }

    $control = RouteFacade::get('/_bfc-standalone-inventory-control', [FutureLocalAuthenticationController::class, 'authenticate']);
    $control->setAction([...$control->getAction(), 'bfc_standalone_owned' => true]);
    $discoveredControl = array_values(array_filter(
        StandaloneSurfaceInventory::routes($router),
        static fn (Route $route): bool => $route === $control,
    ));
    $unexpectedControllers = array_values(array_diff(
        array_unique(array_map(StandaloneSurfaceInventory::controller(...), StandaloneSurfaceInventory::routes($router))),
        $expectedControllers,
    ));

    expect($discoveredControl)->toHaveCount(1)
        ->and($unexpectedControllers)->toBe([FutureLocalAuthenticationController::class])
        ->and($router->gatherRouteMiddleware($discoveredControl[0]))
        ->not->toContain(EnsureStandaloneAuthority::class);
});
