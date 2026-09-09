<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureStandaloneAuthority;
use ArtisanBuild\BuiltForCloud\Http\Middleware\PreventBearerUrlPersistence;
use ArtisanBuild\BuiltForCloud\Http\Middleware\RestoreBearerRequestClassification;
use Illuminate\Contracts\Http\Kernel as KernelContract;
use Illuminate\Http\Request;
use Illuminate\Routing\Events\RouteMatched;
use Illuminate\Routing\Router;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Symfony\Component\Process\Process;

it('fails thin-host boot on reserved standalone collisions and middleware exclusion', function (string $collision): void {
    $process = new Process([PHP_BINARY, __DIR__.'/Fixtures/standalone-route-collision.php', $collision]);
    $process->run();

    expect($process->getExitCode())->toBe(0, $process->getErrorOutput())
        ->and($process->getOutput())->toContain('reserved by built-for-cloud standalone authentication');
})->with(['name', 'pair', 'middleware']);

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

it('keeps exactly one host session starter on each bearer page', function (): void {
    /** @var Router $router */
    $router = app('router');
    $bearerPages = ['bfc.password.reset', 'bfc.invitations.accept'];
    app(KernelContract::class);

    foreach ($bearerPages as $name) {
        $route = Route::getRoutes()->getByName($name);

        expect($route)->not->toBeNull();
        Event::dispatch(new RouteMatched($route, Request::create($route->uri(), 'GET')));
    }

    foreach (Route::getRoutes() as $route) {
        if (! is_string($route->getName()) || ! str_starts_with($route->getName(), 'bfc.')) {
            continue;
        }

        $middleware = $router->gatherRouteMiddleware($route);

        if (! in_array($route->getName(), $bearerPages, true)) {
            expect($middleware)
                ->not->toContain(PreventBearerUrlPersistence::class)
                ->not->toContain(RestoreBearerRequestClassification::class);

            continue;
        }

        $sessionMiddleware = array_values(array_filter(
            $middleware,
            static fn (mixed $name): bool => is_string($name) && is_a($name, StartSession::class, true),
        ));

        $sessionIndex = array_search(StartSession::class, $middleware, true);

        expect($sessionMiddleware)->toBe([StartSession::class])
            ->and($middleware[$sessionIndex - 1] ?? null)->toBe(RestoreBearerRequestClassification::class)
            ->and($middleware[$sessionIndex + 1] ?? null)->toBe(PreventBearerUrlPersistence::class)
            ->and($sessionIndex)->toBeLessThan(array_search(EnsureStandaloneAuthority::class, $middleware, true))
            ->and(app(StartSession::class))->toBeInstanceOf(StartSession::class)
            ->not->toBeInstanceOf(PreventBearerUrlPersistence::class);
    }
});
