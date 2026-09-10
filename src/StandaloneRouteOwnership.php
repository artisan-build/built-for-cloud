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
     * Ownership is asserted through stable structural facts — reserved name,
     * domain, URI, methods and package action — because a compiled route
     * collection reconstructs Route instances from cached attributes on
     * lookup, so object identity can never recognise the package's own
     * routes after `route:cache`. The effective authority check resolves the
     * candidate's declared middleware and exclusions through the router's
     * alias and group tables, so spellings that resolve away from the
     * authority class — or exclusions that resolve ONTO it — fail closed.
     *
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

            if (count($named) !== 1
                || ! self::occupiesReservedShape($named[0], $ownedRoute)
                || ! in_array(
                    EnsureStandaloneAuthority::class,
                    $router->resolveMiddleware($named[0]->middleware(), $named[0]->excludedMiddleware()),
                    true,
                )) {
                throw new RuntimeException("The route name [{$name}] is reserved by built-for-cloud standalone authentication.");
            }

            $domainAndUri = $ownedRoute->getDomain().$ownedRoute->uri();

            foreach ($ownedRoute->methods() as $method) {
                $occupant = $byMethod[$method][$domainAndUri] ?? null;

                if (! $occupant instanceof Route || ! self::occupiesReservedShape($occupant, $ownedRoute)) {
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

    /**
     * A route occupies the reserved shape when its stable structural facts —
     * name, domain, URI, method set and controller action — are exactly the
     * package's, which survives compilation/reconstruction. What is pinned
     * is the identity facts plus (in assertOwned) the authority — never the
     * rest of the stack, by design. Named residue: a host clone reproducing
     * every structural fact including the package's own controller action,
     * and carrying the authority, is accepted as the owner; the measured
     * consequence is a fail-closed broken route (request ends 500, nothing
     * completes or persists), not a takeover — reaching it requires the
     * host to name the package's controller at the reserved name and URI.
     */
    private static function occupiesReservedShape(Route $candidate, Route $ownedRoute): bool
    {
        return $candidate->getName() === $ownedRoute->getName()
            && $candidate->getDomain() === $ownedRoute->getDomain()
            && $candidate->uri() === $ownedRoute->uri()
            && array_diff($candidate->methods(), $ownedRoute->methods()) === []
            && array_diff($ownedRoute->methods(), $candidate->methods()) === []
            && $candidate->getActionName() === $ownedRoute->getActionName();
    }
}
