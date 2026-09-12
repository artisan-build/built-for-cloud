<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Support;

use ArtisanBuild\BuiltForCloud\Http\Controllers\StandaloneAuthentication;
use ArtisanBuild\BuiltForCloud\Http\Controllers\StandaloneInvitations;
use ArtisanBuild\BuiltForCloud\Http\Controllers\StandaloneMemberships;
use ArtisanBuild\BuiltForCloud\Http\Controllers\StandalonePasswordRecovery;
use ArtisanBuild\BuiltForCloud\Http\Controllers\StandaloneSessions;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;

final class StandaloneSurfaceInventory
{
    /** @return list<class-string> */
    public static function requiredControllerFamilies(): array
    {
        return [
            StandaloneAuthentication::class,
            StandalonePasswordRecovery::class,
            StandaloneInvitations::class,
            StandaloneMemberships::class,
            StandaloneSessions::class,
        ];
    }

    /** @return list<Route> */
    public static function routes(Router $router): array
    {
        $routes = array_values(array_filter(
            iterator_to_array($router->getRoutes()),
            static fn (Route $route): bool => ($route->getAction()['bfc_standalone_owned'] ?? false) === true,
        ));

        usort($routes, static fn (Route $left, Route $right): int => [
            $left->uri(),
            $left->methods()[0] ?? '',
        ] <=> [
            $right->uri(),
            $right->methods()[0] ?? '',
        ]);

        return $routes;
    }

    public static function controller(Route $route): string
    {
        return explode('@', $route->getActionName(), 2)[0];
    }
}
