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
                || ! in_array(EnsureStandaloneAuthority::class, $ownedRoute->middleware(), true)
                || in_array(EnsureStandaloneAuthority::class, $ownedRoute->excludedMiddleware(), true)) {
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

    /**
     * @param  list<Route>  $ownedRoutes
     */
    public static function assertMatched(Router $router, Route $matchedRoute, array $ownedRoutes): void
    {
        foreach ($ownedRoutes as $ownedRoute) {
            if ($matchedRoute === $ownedRoute
                || $matchedRoute->getName() === $ownedRoute->getName()
                || self::sharesMethodAndUri($matchedRoute, $ownedRoute)) {
                self::assertOwned($router, $ownedRoutes);

                return;
            }
        }
    }

    private static function sharesMethodAndUri(Route $route, Route $ownedRoute): bool
    {
        return $route->getDomain() === $ownedRoute->getDomain()
            && $route->uri() === $ownedRoute->uri()
            && array_intersect($route->methods(), $ownedRoute->methods()) !== [];
    }
}
