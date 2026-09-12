<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Support;

use ArtisanBuild\BuiltForCloud\Http\Controllers\ConsoleChromeScript;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ConsoleEnter;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ConsoleVitals;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageConsoleKeys;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageCredentials;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManagedAuthentication;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageOnboarding;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageOwnership;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageSubjects;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageTransitions;
use ArtisanBuild\BuiltForCloud\Http\Controllers\MetaController;
use ArtisanBuild\BuiltForCloud\Http\Controllers\PersonalCredentials;
use ArtisanBuild\BuiltForCloud\Http\Controllers\StandaloneAuthentication;
use ArtisanBuild\BuiltForCloud\Http\Controllers\StandaloneInvitations;
use ArtisanBuild\BuiltForCloud\Http\Controllers\StandaloneMemberships;
use ArtisanBuild\BuiltForCloud\Http\Controllers\StandalonePasswordRecovery;
use ArtisanBuild\BuiltForCloud\Http\Controllers\StandaloneSessions;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;

final class StandaloneSurfaceInventory
{
    private const string PACKAGE_CONTROLLER_NAMESPACE = 'ArtisanBuild\\BuiltForCloud\\Http\\Controllers\\';

    /** @return array<class-string, bool> */
    public static function expectedControllerFamilies(): array
    {
        return [
            ConsoleChromeScript::class => false,
            ConsoleEnter::class => false,
            ConsoleVitals::class => false,
            ManageConsoleKeys::class => false,
            ManageCredentials::class => false,
            ManagedAuthentication::class => false,
            ManageOnboarding::class => false,
            ManageOwnership::class => false,
            ManageSubjects::class => false,
            ManageTransitions::class => false,
            MetaController::class => false,
            PersonalCredentials::class => false,
            StandaloneAuthentication::class => true,
            StandaloneInvitations::class => true,
            StandaloneMemberships::class => true,
            StandalonePasswordRecovery::class => true,
            StandaloneSessions::class => true,
        ];
    }

    /** @return list<class-string> */
    public static function requiredControllerFamilies(): array
    {
        return array_keys(array_filter(self::expectedControllerFamilies()));
    }

    /** @return list<Route> */
    public static function packageRoutes(Router $router): array
    {
        return self::sortedRoutes(array_values(array_filter(
            $router->getRoutes()->getRoutes(),
            static fn (Route $route): bool => str_starts_with(
                self::controller($route),
                self::PACKAGE_CONTROLLER_NAMESPACE,
            ),
        )));
    }

    /** @return list<Route> */
    public static function routes(Router $router): array
    {
        $required = array_fill_keys(self::requiredControllerFamilies(), true);

        return self::sortedRoutes(array_values(array_filter(
            self::packageRoutes($router),
            static fn (Route $route): bool => isset($required[self::controller($route)]),
        )));
    }

    /**
     * @param  list<Route>  $routes
     * @return list<Route>
     */
    private static function sortedRoutes(array $routes): array
    {
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
