<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\Http\Controllers\PersonalCredentials;
use Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse;
use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Routing\Route as RoutingRoute;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Route;

/**
 * Rework Fix 1, the PREFERRED branch: when the host app registers a `web`
 * middleware group — every standard Laravel app does — the personal
 * surface rides THAT group rather than a second, divergent copy of the
 * session stack. The app's own cookie encryption, session driver, CSRF
 * customization and any middleware it added (locale, tenancy,
 * impersonation) then apply to its own settings screen, which is the
 * point.
 *
 * PHPUnit-style on purpose: the group must exist on the router BEFORE the
 * package provider boots and mounts its routes, so it is registered in
 * getEnvironmentSetUp — per-method config attributes are too late.
 * (Testbench's package app registers no middleware groups at all, which
 * is exactly the fallback shape PersonalCredentialsTest exercises.)
 */
final class PersonalSurfaceWebGroupTest extends TestCase
{
    use RefreshDatabase;

    /**
     * @param  Application  $app
     */
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['router']->middlewareGroup('web', [
            EncryptCookies::class,
            AddQueuedCookiesToResponse::class,
            StartSession::class,
            PreventRequestForgery::class,
        ]);
    }

    public function test_the_personal_routes_ride_the_hosts_own_web_group_when_it_exists(): void
    {
        $personal = collect(Route::getRoutes()->getRoutes())
            ->filter(fn (RoutingRoute $route): bool => str_starts_with($route->uri(), 'bfc/me/'));

        $this->assertCount(3, $personal);

        foreach ($personal as $route) {
            $this->assertContains('web', $route->gatherMiddleware());

            // Resolved through the group: session start and CSRF are
            // really in force, not merely named.
            $resolved = $this->app['router']->gatherRouteMiddleware($route);

            $this->assertContains(StartSession::class, $resolved);
            $this->assertContains(PreventRequestForgery::class, $resolved);
        }
    }

    /**
     * The other package surfaces are token APIs and must NOT be dragged
     * onto the session stack by this change — a bearer-only route that
     * starts a session and validates CSRF would break every machine
     * caller.
     */
    public function test_no_other_package_route_gains_the_session_stack(): void
    {
        $sessioned = collect(Route::getRoutes()->getRoutes())
            ->filter(fn (RoutingRoute $route): bool => str_starts_with($route->getActionName(), 'ArtisanBuild\\BuiltForCloud\\'))
            ->reject(fn (RoutingRoute $route): bool => str_starts_with($route->uri(), 'bfc/me/'))
            ->filter(fn (RoutingRoute $route): bool => in_array(
                StartSession::class,
                $this->app['router']->gatherRouteMiddleware($route),
                true,
            ))
            ->map(fn (RoutingRoute $route): string => $route->methods()[0].' /'.$route->uri())
            ->values()
            ->all();

        $this->assertSame([], $sessioned);
    }

    public function test_the_personal_controller_is_the_only_action_behind_that_stack(): void
    {
        $personal = collect(Route::getRoutes()->getRoutes())
            ->filter(fn (RoutingRoute $route): bool => str_starts_with($route->uri(), 'bfc/me/'))
            ->map(fn (RoutingRoute $route): string => $route->getActionName())
            ->unique()
            ->values()
            ->all();

        $this->assertSame([
            PersonalCredentials::class.'@index',
            PersonalCredentials::class.'@store',
            PersonalCredentials::class.'@destroy',
        ], $personal);
    }
}
