<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Http\Controllers\ClientObservations;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ConsoleChromeScript;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ConsoleVitals;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageConsoleKeys;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageCredentials;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageOnboarding;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageOwnership;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageSubjects;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureConsoleSession;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureDashboardCredential;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureStandaloneAuthority;
use Illuminate\Http\Request;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use RuntimeException;

final class StandaloneRouteOwnership
{
    private const string EXECUTED_GATES = 'bfc.operator_gates_executed';

    private const string PACKAGE_MIDDLEWARE_NAMESPACE = __NAMESPACE__.'\\Http\\Middleware\\';

    /**
     * Record the exact gate and ability that granted passage. The operator
     * controller checks this executed state at the point of no return, rather
     * than relying only on a listener-time prediction of the eventual stack.
     *
     * @internal For package middleware only.
     */
    public static function markOperatorGateExecuted(Request $request, string $gate): void
    {
        $executed = $request->attributes->get(self::EXECUTED_GATES, []);
        $executed = is_array($executed) ? $executed : [];
        $executed[] = $gate;

        $request->attributes->set(self::EXECUTED_GATES, $executed);
    }

    public static function assertOperatorGateExecuted(Request $request, Route $route, string $gate): void
    {
        $executed = $request->attributes->get(self::EXECUTED_GATES, []);

        if (! is_array($executed) || ! in_array($gate, $executed, true)) {
            $method = $route->methods()[0] ?? 'UNKNOWN';

            throw new RuntimeException("The route [{$method} {$route->uri()}] did not execute its built-for-cloud operator gate [{$gate}].");
        }
    }

    public static function operatorGateForAction(string $action): ?string
    {
        return match ($action) {
            ManageOwnership::class.'@claim',
            ManageOnboarding::class.'@claim',
            ManageOnboarding::class.'@exchange',
            ManageOnboarding::class.'@verify' => null,
            ManageOwnership::class.'@release',
            ManageOwnership::class.'@cancelTransfer' => EnsureCredentialAdmin::class.':'.OperatorAbility::OwnershipRelease->value,
            ManageOnboarding::class.'@issue' => EnsureCredentialAdmin::class.':'.OperatorAbility::CredentialMint->value,
            ClientObservations::class => EnsureCredentialAdmin::class.':'.OperatorAbility::CredentialRead->value,
            ManageCredentials::class.'@index' => EnsureCredentialAdmin::class.':'.OperatorAbility::CredentialRead->value,
            ManageCredentials::class.'@store' => EnsureCredentialAdmin::class.':'.OperatorAbility::CredentialMint->value,
            ManageCredentials::class.'@destroy' => EnsureCredentialAdmin::class.':'.OperatorAbility::CredentialRevoke->value,
            ManageCredentials::class.'@rotate',
            ManageCredentials::class.'@activate' => EnsureCredentialAdmin::class.':'.OperatorAbility::CredentialRotate->value,
            ManageConsoleKeys::class.'@reKey',
            ManageConsoleKeys::class.'@retire' => EnsureCredentialAdmin::class.':'.OperatorAbility::ConsoleKeyWrite->value,
            ManageSubjects::class.'@offboard' => EnsureCredentialAdmin::class.':'.OperatorAbility::SubjectOffboard->value,
            ConsoleChromeScript::class => EnsureConsoleSession::class,
            ConsoleVitals::class => EnsureDashboardCredential::class,
            default => throw new RuntimeException("The package controller action [{$action}] is missing from the operator route inventory."),
        };
    }

    /**
     * Operator routes have no reserved names, so ownership is the exact
     * domain, URI, method set and package action captured when each route is
     * mounted. The expected gate is supplied independently of the candidate's
     * declaration, making a missing or misspelled declaration a refusal rather
     * than a route that silently falls out of the inventory.
     *
     * @param  list<array{route: Route, gate: string}>  $ownedRoutes
     */
    public static function assertOperatorOwned(Router $router, array $ownedRoutes): void
    {
        $byMethod = $router->getRoutes()->getRoutesByMethod();

        foreach ($ownedRoutes as ['route' => $ownedRoute, 'gate' => $gate]) {
            $domainAndUri = $ownedRoute->getDomain().$ownedRoute->uri();

            foreach ($ownedRoute->methods() as $method) {
                $candidate = $byMethod[$method][$domainAndUri] ?? null;

                if (! $candidate instanceof Route
                    || ! self::occupiesOperatorShape($candidate, $ownedRoute)
                    || ! self::resolvesGate($router, $candidate, $gate)) {
                    throw new RuntimeException("The route [{$method} {$ownedRoute->uri()}] must retain its built-for-cloud operator gate [{$gate}].");
                }
            }
        }
    }

    /**
     * @param  list<array{route: Route, gate: string}>  $ownedRoutes
     */
    public static function assertOperatorMatched(Router $router, Route $matchedRoute, array $ownedRoutes): void
    {
        foreach ($ownedRoutes as ['route' => $ownedRoute, 'gate' => $gate]) {
            if (! self::sharesMethodAndUri($matchedRoute, $ownedRoute)) {
                continue;
            }

            if (! self::occupiesOperatorShape($matchedRoute, $ownedRoute)
                || ! self::resolvesGate($router, $matchedRoute, $gate)) {
                $method = $matchedRoute->methods()[0] ?? 'UNKNOWN';

                throw new RuntimeException("The route [{$method} {$ownedRoute->uri()}] must retain its built-for-cloud operator gate [{$gate}].");
            }

            return;
        }
    }

    /**
     * Snapshot FQCN-spelled package middleware when each route is registered,
     * independently of the mutable route collection checked later. An alias-
     * spelled declaration such as `bfc.auth` carries no package namespace, so
     * it is not inventoried or pinned; package routes currently spell their
     * package gates as FQCNs.
     *
     * @param  list<Route>  $routes
     * @return list<array{route: Route, middleware: list<string>}>
     */
    public static function packageMiddlewareInventory(array $routes): array
    {
        return array_map(
            static fn (Route $route): array => [
                'route' => $route,
                'middleware' => self::packageMiddleware($route),
            ],
            $routes,
        );
    }

    /**
     * Resolve every inventoried package middleware declaration at boot and
     * match time. At match, discard any earlier computed stack so uncached and
     * compiled routes recompute from the declaration just asserted. This is
     * still a prediction made one instruction before runRouteWithinStack()
     * builds the pipeline: a later RouteMatched listener can mutate the memo,
     * alias or group tables, or route exclusions in that window. A container
     * rebind can also replace a gate without changing its resolved class name.
     * Standalone controllers issue no execution receipt, which is the check
     * required to close those remaining seams.
     *
     * @param  list<array{route: Route, middleware: list<string>}>  $ownedRoutes
     */
    public static function assertPackageMiddlewareOwned(Router $router, array $ownedRoutes): void
    {
        $byMethod = $router->getRoutes()->getRoutesByMethod();

        foreach ($ownedRoutes as ['route' => $ownedRoute, 'middleware' => $middleware]) {
            $domainAndUri = $ownedRoute->getDomain().$ownedRoute->uri();

            foreach ($ownedRoute->methods() as $method) {
                $candidate = $byMethod[$method][$domainAndUri] ?? null;

                if (! $candidate instanceof Route || ! self::occupiesOperatorShape($candidate, $ownedRoute)) {
                    throw new RuntimeException("The route [{$method} {$ownedRoute->uri()}] must retain its built-for-cloud package middleware.");
                }

                foreach ($middleware as $expected) {
                    if (! self::resolvesGate($router, $candidate, $expected)) {
                        throw new RuntimeException("The route [{$method} {$ownedRoute->uri()}] must retain its built-for-cloud package middleware [{$expected}].");
                    }
                }
            }
        }
    }

    /**
     * @param  list<array{route: Route, middleware: list<string>}>  $ownedRoutes
     */
    public static function assertPackageMiddlewareMatched(Router $router, Route $matchedRoute, array $ownedRoutes): void
    {
        foreach ($ownedRoutes as ['route' => $ownedRoute]) {
            if (self::sharesMethodAndUri($matchedRoute, $ownedRoute)) {
                $matchedRoute->flushController();
                self::assertPackageMiddlewareOwned($router, $ownedRoutes);

                return;
            }
        }
    }

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

    private static function occupiesOperatorShape(Route $candidate, Route $ownedRoute): bool
    {
        return $candidate->getDomain() === $ownedRoute->getDomain()
            && $candidate->uri() === $ownedRoute->uri()
            && array_diff($candidate->methods(), $ownedRoute->methods()) === []
            && array_diff($ownedRoute->methods(), $candidate->methods()) === []
            && $candidate->getActionName() === $ownedRoute->getActionName();
    }

    /** @return list<string> */
    private static function packageMiddleware(Route $route): array
    {
        $packageMiddleware = [];

        foreach ($route->middleware() as $middleware) {
            if (! is_string($middleware)) {
                continue;
            }

            $class = explode(':', $middleware, 2)[0];

            if (str_starts_with($class, self::PACKAGE_MIDDLEWARE_NAMESPACE)) {
                $packageMiddleware[] = $middleware;
            }
        }

        return array_values(array_unique($packageMiddleware));
    }

    private static function resolvesGate(Router $router, Route $route, string $gate): bool
    {
        return in_array(
            $gate,
            $router->resolveMiddleware($route->middleware(), $route->excludedMiddleware()),
            true,
        );
    }
}
