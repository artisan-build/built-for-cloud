<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureStandaloneAuthority;
use Illuminate\Routing\Router;
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
