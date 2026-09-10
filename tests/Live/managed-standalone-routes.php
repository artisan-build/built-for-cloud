<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureStandaloneAuthority;
use ArtisanBuild\BuiltForCloud\Tests\Support\StandaloneSurfaceInventory;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Routing\Router;

require __DIR__.'/../../vendor/autoload.php';

$app = require __DIR__.'/../../vendor/orchestra/testbench-core/laravel/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();

/** @var Router $router */
$router = $app->make('router');
$routes = StandaloneSurfaceInventory::routes($router);
$controllers = array_values(array_unique(array_map(
    StandaloneSurfaceInventory::controller(...),
    $routes,
)));

foreach (StandaloneSurfaceInventory::requiredControllerFamilies() as $controller) {
    if (! in_array($controller, $controllers, true)) {
        throw new RuntimeException("The live standalone inventory is missing controller family [{$controller}].");
    }
}

foreach ($routes as $route) {
    if (! in_array(EnsureStandaloneAuthority::class, $router->gatherRouteMiddleware($route), true)) {
        throw new RuntimeException("The live standalone route [{$route->uri()}] does not resolve the standalone authority gate.");
    }

    $name = $route->getName();

    if (! is_string($name) || $name === '') {
        throw new RuntimeException("The live standalone route [{$route->uri()}] has no stable name.");
    }

    $path = preg_replace('/\{[^}]+\}/', 'bfc-live-sentinel', $route->uri());

    if (! is_string($path)) {
        throw new RuntimeException("The live standalone route [{$route->uri()}] could not be materialized.");
    }

    $controller = StandaloneSurfaceInventory::controller($route);
    $surface = str_replace('ArtisanBuild\\BuiltForCloud\\Http\\Controllers\\Standalone', '', $controller);

    foreach (array_diff($route->methods(), ['HEAD']) as $method) {
        fwrite(STDOUT, implode("\t", [$surface, $name, $method, '/'.$path]).PHP_EOL);
    }
}
