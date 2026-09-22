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
            ->filter(fn (RoutingRoute $route): bool => str_starts_with($route->uri(), 'bfc/me/credentials'));

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
     * Package routes not enumerated below are token APIs and must NOT be dragged
     * onto the session stack — a bearer-only route that
     * starts a session and validates CSRF would break every machine
     * caller.
     *
     * Every session-riding package route is named here rather than excluded
     * by a broad pattern. The installation-credential entries intentionally
     * join the personal surface on the browser stack.
     *
     * The delegated-entry door (`POST /bfc/console/enter`) and the
     * console chrome's re-entry interceptor (`GET /bfc/console/chrome.js`)
     * were the two non-personal browser routes this enumeration once
     * carried; both were retired in v0.17.0, so the set below is the
     * personal, installation, standalone and authorization surfaces
     * alone.
     *
     * So the assertion below is a SET, not an emptiness: adding a new
     * session-riding route means saying so in this diff.
     * The managed login and callback are browser routes that require the
     * initiating session's nonce to prevent login CSRF.
     * Device and loopback creation/decision routes also require this stack;
     * their two public token exchanges must remain absent from this exact set.
     */
    public function test_only_package_browser_routes_ride_the_session_stack(): void
    {
        $sessioned = collect(Route::getRoutes()->getRoutes())
            ->filter(fn (RoutingRoute $route): bool => str_starts_with($route->getActionName(), 'ArtisanBuild\\BuiltForCloud\\'))
            ->reject(fn (RoutingRoute $route): bool => str_starts_with($route->uri(), 'bfc/me/'))
            ->filter(fn (RoutingRoute $route): bool => collect($this->app['router']->gatherRouteMiddleware($route))
                ->contains(static fn (mixed $middleware): bool => is_string($middleware)
                    && is_a($middleware, StartSession::class, true)))
            ->map(fn (RoutingRoute $route): string => $route->methods()[0].' /'.$route->uri())
            ->values()
            ->all();

        sort($sessioned);

        $this->assertSame([
            'DELETE /bfc/installation/credentials/{id}',
            'DELETE /bfc/members/{user}',
            'DELETE /bfc/ui/credentials/installation/{id}',
            'DELETE /bfc/ui/credentials/personal/{id}',
            'GET /bfc/device',
            'GET /bfc/forgot-password',
            'GET /bfc/installation/credentials',
            'GET /bfc/invitations/accept',
            'GET /bfc/login',
            'GET /bfc/loopback/authorize',
            'GET /bfc/managed/callback',
            'GET /bfc/managed/login',
            'GET /bfc/members',
            'GET /bfc/reset-password',
            'GET /bfc/transitions/proposals/{transition}',
            'GET /bfc/transitions/{direction}/prepare',
            'GET /bfc/ui',
            'GET /bfc/ui/credentials/installation',
            'GET /bfc/ui/credentials/personal',
            'POST /bfc/device',
            'POST /bfc/device-authorizations',
            'POST /bfc/forgot-password',
            'POST /bfc/installation/credentials',
            'POST /bfc/installation/credentials/{id}/rotate',
            'POST /bfc/invitations/accept',
            'POST /bfc/login',
            'POST /bfc/logout',
            'POST /bfc/loopback/authorize',
            'POST /bfc/members/invitations',
            'POST /bfc/reset-password',
            'POST /bfc/transitions/proposals/{transition}/abandon',
            'POST /bfc/transitions/proposals/{transition}/complete',
            'POST /bfc/transitions/{direction}/prepare',
            'POST /bfc/ui/credentials/installation',
            'POST /bfc/ui/credentials/installation/{id}/rotate',
            'POST /bfc/ui/credentials/personal',
            'POST /bfc/ui/credentials/personal/{id}/rotate',
            'POST /bfc/ui/logout',
            'PUT /bfc/members/{user}/role',
            'PUT /bfc/transitions/proposals/{transition}',
        ], $sessioned);
    }



    public function test_the_personal_controller_is_the_only_action_behind_that_stack(): void
    {
        $personal = collect(Route::getRoutes()->getRoutes())
            ->filter(fn (RoutingRoute $route): bool => str_starts_with($route->uri(), 'bfc/me/credentials'))
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
