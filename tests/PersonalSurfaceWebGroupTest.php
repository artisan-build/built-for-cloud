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
     *
     * THE ENUMERATION HAS EXACTLY TWO MEMBERS, and each is named here
     * rather than excluded by a pattern.
     *
     * `POST /bfc/console/enter` is a BROWSER route by construction: it
     * exists to create a delegated session, so it cannot do its job
     * without starting one (Console PRD D12/D13, PR4). What it
     * deliberately does NOT ride is the host's `web` GROUP, which is
     * where the personal surface goes — and the difference is the point.
     * The group carries CSRF validation, and the console handoff is a
     * cross-site POST from the issuer's page: a `SameSite=Lax` session
     * cookie is not sent with one, so the app has no session with that
     * browser and no token it could have planted. What stands in for the
     * token is the vendor's signature over the return path (D13's signed
     * state), the assertion's 60-120s TTL and its single-use burn.
     *
     * `GET /bfc/console/chrome.js` is the console chrome's re-entry
     * interceptor (Console PRD D7/D11, PR5), and it starts a session for
     * the opposite reason: it READS the delegated one. It is a browser
     * route serving a browser, gated on the delegated session like the
     * page that loads it, so it rides the host's `web` group exactly as
     * the personal surface does.
     *
     * So the assertion below is a SET, not an emptiness: adding a third
     * session-riding route means saying so in this diff.
     */
    public function test_only_the_personal_surface_and_the_console_browser_routes_ride_the_session_stack(): void
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

        sort($sessioned);

        $this->assertSame(['GET /bfc/console/chrome.js', 'POST /bfc/console/enter'], $sessioned);
    }

    /**
     * The chrome asset takes the OTHER branch: the host's own `web`
     * group, like the personal surface, because it is an ordinary
     * same-site GET from the app's own page and there is nothing about
     * it that needs a second, divergent session stack.
     */
    public function test_the_chrome_interceptor_rides_the_hosts_own_web_group(): void
    {
        $chrome = collect(Route::getRoutes()->getRoutes())
            ->sole(fn (RoutingRoute $route): bool => $route->uri() === 'bfc/console/chrome.js');

        $this->assertContains('web', $chrome->gatherMiddleware());

        $resolved = $this->app['router']->gatherRouteMiddleware($chrome);

        $this->assertContains(StartSession::class, $resolved);
        $this->assertContains(EncryptCookies::class, $resolved);
    }

    /**
     * …and the door is on the CONCRETE stack rather than the host's
     * `web` group, which is the half the enumeration above cannot say.
     */
    public function test_the_console_door_starts_a_session_without_csrf_validation(): void
    {
        $door = collect(Route::getRoutes()->getRoutes())
            ->sole(fn (RoutingRoute $route): bool => $route->uri() === 'bfc/console/enter');

        $resolved = $this->app['router']->gatherRouteMiddleware($door);

        $this->assertContains(StartSession::class, $resolved);
        $this->assertContains(EncryptCookies::class, $resolved);
        $this->assertNotContains(PreventRequestForgery::class, $resolved);
        $this->assertNotContains('web', $door->gatherMiddleware());
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
