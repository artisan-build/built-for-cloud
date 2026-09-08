<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureStandaloneAuthority;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use RuntimeException;

final class StandaloneRouteOwnership
{
    /**
     * @param  list<Route>  $ownedRoutes
     */
    public static function assertOwned(Router $router, array $ownedRoutes): void
    {
        $routes = $router->getRoutes();
        $allRoutes = $routes->getRoutes();
        $byMethod = $routes->getRoutesByMethod();

        foreach ($ownedRoutes as $ownedRoute) {
            $name = $ownedRoute->getName();

            if (! is_string($name) || $name === '') {
                throw new RuntimeException('A built-for-cloud standalone route is missing its reserved name.');
            }

            $named = array_values(array_filter(
                $allRoutes,
                static fn (Route $route): bool => $route->getName() === $name,
            ));

            if ($named !== [$ownedRoute]
                || ! in_array(EnsureStandaloneAuthority::class, $router->gatherRouteMiddleware($ownedRoute), true)) {
                throw new RuntimeException("The route name [{$name}] is reserved by built-for-cloud standalone authentication.");
            }

            $domainAndUri = $ownedRoute->getDomain().$ownedRoute->uri();

            foreach ($ownedRoute->methods() as $method) {
                if (($byMethod[$method][$domainAndUri] ?? null) !== $ownedRoute) {
                    throw new RuntimeException("The route [{$method} {$ownedRoute->uri()}] is reserved by built-for-cloud standalone authentication.");
                }
            }
        }
    }
}
