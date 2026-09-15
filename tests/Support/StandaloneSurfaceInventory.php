<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Support;

use ArtisanBuild\BuiltForCloud\Http\Controllers\AsymmetricEnrollments;
use ArtisanBuild\BuiltForCloud\Http\Controllers\BoundHmacCutovers;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ClientObservations;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ConsoleChromeScript;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ConsoleEnter;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ConsoleVitals;
use ArtisanBuild\BuiltForCloud\Http\Controllers\InstallationCredentials;
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
use ArtisanBuild\BuiltForCloud\Http\Controllers\UiHome;
use ArtisanBuild\BuiltForCloud\Http\Controllers\UiInstallationCredentials;
use ArtisanBuild\BuiltForCloud\Http\Controllers\UiLogout;
use ArtisanBuild\BuiltForCloud\Http\Controllers\UiPersonalCredentials;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureStandaloneAuthority;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;

final class StandaloneSurfaceInventory
{
    /** @var list<string> */
    private const array STANDALONE_PATHS = [
        'bfc/forgot-password',
        'bfc/invitations',
        'bfc/login',
        'bfc/logout',
        'bfc/me/sessions',
        'bfc/members',
        'bfc/reset-password',
    ];

    /** @return array<class-string, bool> */
    public static function expectedControllerFamilies(): array
    {
        return [
            AsymmetricEnrollments::class => false,
            BoundHmacCutovers::class => false,
            ClientObservations::class => false,
            ConsoleChromeScript::class => false,
            ConsoleEnter::class => false,
            ConsoleVitals::class => false,
            InstallationCredentials::class => false,
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
            UiHome::class => false,
            UiInstallationCredentials::class => false,
            UiLogout::class => false,
            UiPersonalCredentials::class => false,
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
            static fn (Route $route): bool => $route->uri() === 'bfc'
                || str_starts_with($route->uri(), 'bfc/'),
        )));
    }

    /** @return list<Route> */
    public static function routes(Router $router): array
    {
        return self::sortedRoutes(array_values(array_filter(
            self::packageRoutes($router),
            static fn (Route $route): bool => self::isStandalonePath($route->uri())
                || in_array(EnsureStandaloneAuthority::class, $router->gatherRouteMiddleware($route), true),
        )));
    }

    private static function isStandalonePath(string $uri): bool
    {
        foreach (self::STANDALONE_PATHS as $path) {
            if ($uri === $path || str_starts_with($uri, $path.'/')) {
                return true;
            }
        }

        return false;
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
