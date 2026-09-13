<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureConsoleSession;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureDashboardCredential;
use Symfony\Component\Process\Process;

it('derives the complete operator route inventory with and without the console', function (bool $console, int $expected): void {
    $repoRoot = dirname(__DIR__);
    $artisan = $repoRoot.'/vendor/orchestra/testbench-core/laravel/artisan';
    $process = new Process(
        [PHP_BINARY, $artisan, 'route:list', '--json'],
        $repoRoot,
        [
            'TESTBENCH_WORKING_PATH' => $repoRoot,
            'BUILT_FOR_CLOUD_CONSOLE_ENABLED' => $console ? 'true' : 'false',
        ],
    );
    $process->mustRun();

    $routes = json_decode($process->getOutput(), true, flags: JSON_THROW_ON_ERROR);
    $gates = [EnsureCredentialAdmin::class, EnsureConsoleSession::class, EnsureDashboardCredential::class];
    $operatorRoutes = array_values(array_filter($routes, static function (array $route) use ($gates): bool {
        foreach ($route['middleware'] as $middleware) {
            foreach ($gates as $gate) {
                if ($middleware === $gate || str_starts_with($middleware, $gate.':')) {
                    return true;
                }
            }
        }

        return false;
    }));

    expect($operatorRoutes)->toHaveCount($expected);
})->with([
    'console enabled' => [true, 14],
    'console disabled' => [false, 13],
]);
