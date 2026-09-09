<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureStandaloneAuthority;
use ArtisanBuild\BuiltForCloud\Http\Middleware\PreventBearerUrlPersistence;
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

it('replaces only bearer page sessions with first-write persistence protection', function (): void {
    /** @var Router $router */
    $router = app('router');
    $bearerPages = ['bfc.password.reset', 'bfc.invitations.accept'];

    foreach (Route::getRoutes() as $route) {
        if (! is_string($route->getName()) || ! str_starts_with($route->getName(), 'bfc.')) {
            continue;
        }

        $middleware = $router->gatherRouteMiddleware($route);

        if (! in_array($route->getName(), $bearerPages, true)) {
            expect($middleware)->not->toContain(PreventBearerUrlPersistence::class);

            continue;
        }

        $sessionMiddleware = array_values(array_filter(
            $middleware,
            static fn (mixed $name): bool => is_string($name) && is_a($name, StartSession::class, true),
        ));

        expect($middleware)->toContain(PreventBearerUrlPersistence::class)
            ->not->toContain(StartSession::class)
            ->and($sessionMiddleware)->toBe([PreventBearerUrlPersistence::class])
            ->and(array_search(PreventBearerUrlPersistence::class, $middleware, true))
            ->toBeLessThan(array_search(EnsureStandaloneAuthority::class, $middleware, true));
    }
});
