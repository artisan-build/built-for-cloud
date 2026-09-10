<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureStandaloneAuthority;
use ArtisanBuild\BuiltForCloud\Http\Middleware\ExpireStandaloneHandoffOnRefusal;
use ArtisanBuild\BuiltForCloud\StandaloneRouteOwnership;
use Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse;
use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Routing\Route as RoutingRoute;
use Illuminate\Routing\Router;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Route;
use Symfony\Component\Process\Process;

it('fails thin-host boot on reserved standalone collisions and middleware exclusion', function (string $collision): void {
    $process = new Process([PHP_BINARY, __DIR__.'/Fixtures/standalone-route-collision.php', $collision]);
    $process->run();

    expect($process->getExitCode())->toBe(0, $process->getErrorOutput())
        ->and($process->getOutput())->toContain('reserved by built-for-cloud standalone authentication');
})->with(['name', 'pair', 'middleware']);

it('refuses reserved standalone collisions registered by a later booted callback', function (string $collision): void {
    $process = new Process([PHP_BINARY, __DIR__.'/Fixtures/standalone-route-collision.php', $collision]);
    $process->run();

    expect($process->getExitCode())->toBe(0, $process->getOutput().$process->getErrorOutput())
        ->and($process->getOutput())->toContain('refused before the host handler');
})->with(['late-name', 'late-pair']);

it('keeps the standalone authority gate effective on every owned route', function (): void {
    /** @var Router $router */
    $router = app('router');

    foreach (Route::getRoutes() as $route) {
        if (is_string($route->getName()) && str_starts_with($route->getName(), 'bfc.')) {
            if (! str_starts_with($route->getName(), 'bfc.login')
                && ! str_starts_with($route->getName(), 'bfc.logout')
                && ! str_starts_with($route->getName(), 'bfc.password.')
                && ! str_starts_with($route->getName(), 'bfc.invitations.')
                && ! str_starts_with($route->getName(), 'bfc.members.')
                && ! str_starts_with($route->getName(), 'bfc.sessions.')) {
                continue;
            }

            expect($router->gatherRouteMiddleware($route))->toContain(EnsureStandaloneAuthority::class);
        }
    }
});

it('keeps bearer pages stateless and clean handoff pages on the ordinary session stack', function (): void {
    /** @var Router $router */
    $router = app('router');

    foreach (['bfc.password.reset', 'bfc.invitations.accept'] as $name) {
        $route = Route::getRoutes()->getByName($name);
        expect($route)->not->toBeNull();
        $middleware = $router->gatherRouteMiddleware($route);

        expect($middleware)
            ->toContain(EncryptCookies::class)
            ->toContain(AddQueuedCookiesToResponse::class)
            ->toContain(ExpireStandaloneHandoffOnRefusal::class)
            ->toContain(EnsureStandaloneAuthority::class)
            ->not->toContain('web')
            ->not->toContain(PreventRequestForgery::class);
        expect(array_filter(
            $middleware,
            static fn (mixed $candidate): bool => is_string($candidate)
                && is_a(explode(':', $candidate, 2)[0], StartSession::class, true),
        ))->toBe([]);
        expect($route->excludedMiddleware())->toContain(StartSession::class);
    }

    foreach (['bfc.password.reset.form', 'bfc.password.update', 'bfc.invitations.accept.form', 'bfc.invitations.accept.store'] as $name) {
        $route = Route::getRoutes()->getByName($name);
        expect($route)->not->toBeNull();
        $middleware = $router->gatherRouteMiddleware($route);

        expect($middleware)
            ->toContain(StartSession::class)
            ->toContain(PreventRequestForgery::class)
            ->toContain(EnsureStandaloneAuthority::class);
    }

    expect(app(StartSession::class))->toBeInstanceOf(StartSession::class);
});

it('asserts ownership and refuses resolution attacks without populating the route middleware cache', function (): void {
    /** @var Router $router */
    $router = app('router');

    $names = [
        'bfc.login', 'bfc.login.store', 'bfc.logout',
        'bfc.password.request', 'bfc.password.email',
        'bfc.password.reset', 'bfc.password.reset.form', 'bfc.password.update',
        'bfc.invitations.accept', 'bfc.invitations.accept.form', 'bfc.invitations.accept.store',
        'bfc.members.index', 'bfc.members.invitations.store', 'bfc.members.role.update', 'bfc.members.destroy',
        'bfc.sessions.index', 'bfc.sessions.destroy-others', 'bfc.sessions.destroy',
    ];

    $ownedRoutes = [];

    foreach ($names as $name) {
        $route = Route::getRoutes()->getByName($name);
        expect($route)->not->toBeNull();
        $ownedRoutes[] = $route;
    }

    $computed = new ReflectionProperty(RoutingRoute::class, 'computedMiddleware');
    $computed->setAccessible(true);

    $assertAllUncached = function () use ($computed, $ownedRoutes): void {
        foreach ($ownedRoutes as $route) {
            expect($computed->getValue($route))->toBeNull();
        }
    };

    $assertAllUncached();

    StandaloneRouteOwnership::assertOwned($router, $ownedRoutes);

    $assertAllUncached();

    $router->aliasMiddleware(EnsureStandaloneAuthority::class, AddQueuedCookiesToResponse::class);

    $assertAllUncached();

    expect(fn () => StandaloneRouteOwnership::assertOwned($router, $ownedRoutes))
        ->toThrow(RuntimeException::class, 'reserved by built-for-cloud standalone authentication');

    $assertAllUncached();
});
