<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureStandaloneAuthority;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAuthenticated;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\ManagedTransitionDirection;
use ArtisanBuild\BuiltForCloud\RouteMiddleware;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Routing\Route as RoutingRoute;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;

uses(RefreshDatabase::class);

/** @return array<string, string|null> */
function p3GuardedPackageRouteInventory(): array
{
    /** @var Router $router */
    $router = app('router');
    $inventory = [];

    foreach (Route::getRoutes() as $route) {
        if (! str_starts_with($route->uri(), 'bfc/')
            || RouteMiddleware::indexOfClass(
                $router->gatherRouteMiddleware($route),
                EnsureUserIsAuthenticated::class,
            ) === null) {
            continue;
        }

        foreach (array_diff($route->methods(), ['HEAD']) as $method) {
            $inventory[$method.' '.$route->uri()] = $route->getName();
        }
    }

    ksort($inventory);

    return $inventory;
}

function p3RequestUri(RoutingRoute $route, int $index): string
{
    $parameters = [
        'direction' => ManagedTransitionDirection::Exit->value,
        'id' => 'test-created-id-'.$index,
        'session' => 'test-created-session-'.$index,
        'transition' => 'test-created-transition-'.$index,
        'user' => 'test-created-user-'.$index,
    ];
    $path = preg_replace_callback(
        '/\{([^}:?]+)[^}]*\}/',
        static fn (array $match): string => $parameters[$match[1]] ?? 'test-created-parameter-'.$index,
        $route->uri(),
    );
    expect($path)->toBeString();

    return '/'.$path.'?test-created-destination='.$index;
}

it('pins every package route guarded by the local human authentication gate', function (): void {
    expect(p3GuardedPackageRouteInventory())->toBe([
        'DELETE bfc/installation/credentials/{id}' => null,
        'DELETE bfc/me/credentials/{id}' => null,
        'DELETE bfc/me/sessions/others' => 'bfc.sessions.destroy-others',
        'DELETE bfc/me/sessions/{session}' => 'bfc.sessions.destroy',
        'DELETE bfc/members/{user}' => 'bfc.members.destroy',
        'DELETE bfc/ui/credentials/installation/{id}' => 'bfc.ui.installation-credentials.destroy',
        'DELETE bfc/ui/credentials/personal/{id}' => 'bfc.ui.personal-credentials.destroy',
        'GET bfc/device' => 'bfc.device.show',
        'GET bfc/installation/credentials' => null,
        'GET bfc/loopback/authorize' => 'bfc.loopback.authorize',
        'GET bfc/me/credentials' => null,
        'GET bfc/me/sessions' => 'bfc.sessions.index',
        'GET bfc/members' => 'bfc.members.index',
        'GET bfc/transitions/proposals/{transition}' => 'bfc.transitions.edit',
        'GET bfc/transitions/{direction}/prepare' => 'bfc.transitions.index',
        'GET bfc/ui' => 'bfc.ui.home',
        'GET bfc/ui/credentials/installation' => 'bfc.ui.installation-credentials.index',
        'GET bfc/ui/credentials/personal' => 'bfc.ui.personal-credentials.index',
        'POST bfc/device' => 'bfc.device.decide',
        'POST bfc/device-authorizations' => 'bfc.device.start',
        'POST bfc/installation/credentials' => null,
        'POST bfc/installation/credentials/{id}/rotate' => null,
        'POST bfc/logout' => 'bfc.logout',
        'POST bfc/loopback/authorize' => 'bfc.loopback.decide',
        'POST bfc/me/credentials' => null,
        'POST bfc/members/invitations' => 'bfc.members.invitations.store',
        'POST bfc/transitions/proposals/{transition}/abandon' => 'bfc.transitions.abandon',
        'POST bfc/transitions/proposals/{transition}/complete' => 'bfc.transitions.complete',
        'POST bfc/transitions/{direction}/prepare' => 'bfc.transitions.store',
        'POST bfc/ui/credentials/installation' => 'bfc.ui.installation-credentials.store',
        'POST bfc/ui/credentials/installation/{id}/rotate' => 'bfc.ui.installation-credentials.rotate',
        'POST bfc/ui/credentials/personal' => 'bfc.ui.personal-credentials.store',
        'POST bfc/ui/credentials/personal/{id}/rotate' => 'bfc.ui.personal-credentials.rotate',
        'POST bfc/ui/logout' => 'bfc.ui.logout',
        'PUT bfc/members/{user}/role' => 'bfc.members.role.update',
        'PUT bfc/transitions/proposals/{transition}' => 'bfc.transitions.update',
    ]);
});

it('redirects every managed package route guarded by local human authentication with its intended destination', function (): void {
    DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
        'mode' => AuthorityMode::Managed->value,
        'generation' => 2,
    ]);

    /** @var Router $router */
    $router = app('router');
    $tested = [];

    foreach (Route::getRoutes() as $route) {
        $middleware = $router->gatherRouteMiddleware($route);

        if (! str_starts_with($route->uri(), 'bfc/')
            || RouteMiddleware::indexOfClass($middleware, EnsureUserIsAuthenticated::class) === null
            || RouteMiddleware::indexOfClass($middleware, EnsureStandaloneAuthority::class) !== null) {
            continue;
        }

        $method = array_values(array_diff($route->methods(), ['HEAD']))[0];
        $requestUri = p3RequestUri($route, count($tested));

        $this->call($method, $requestUri)->assertRedirect(route('bfc.managed.login', [
            'intended' => $requestUri,
        ]));
        $tested[] = $method.' '.$route->uri();
    }

    expect($tested)->toHaveCount(28)
        ->and($tested)->toContain('GET bfc/device')
        ->and($tested)->toContain('GET bfc/me/credentials')
        ->and($tested)->toContain('GET bfc/transitions/{direction}/prepare');
});

it('keeps standalone redirects unchanged across every guarded package route', function (): void {
    /** @var Router $router */
    $router = app('router');
    $tested = [];

    foreach (Route::getRoutes() as $route) {
        if (! str_starts_with($route->uri(), 'bfc/')
            || RouteMiddleware::indexOfClass(
                $router->gatherRouteMiddleware($route),
                EnsureUserIsAuthenticated::class,
            ) === null) {
            continue;
        }

        $method = array_values(array_diff($route->methods(), ['HEAD']))[0];
        $requestUri = p3RequestUri($route, count($tested));
        $expected = str_starts_with($route->uri(), 'bfc/ui')
            ? route('bfc.login', ['intended' => $requestUri])
            : route('bfc.login');

        $this->call($method, $requestUri)->assertRedirect($expected);
        $tested[] = $method.' '.$route->uri();
    }

    expect($tested)->toHaveCount(36)
        ->and($tested)->toContain('GET bfc/device')
        ->and($tested)->toContain('POST bfc/logout');
});
