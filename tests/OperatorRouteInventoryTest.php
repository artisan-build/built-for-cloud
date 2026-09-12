<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureAdminToken;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureConsoleSession;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureDashboardCredential;
use Symfony\Component\Process\Process;

it('derives the complete operator route inventory across optional surface combinations', function (bool $console, bool $legacyApi, int $expected): void {
    $repoRoot = dirname(__DIR__);
    $artisan = $repoRoot.'/vendor/orchestra/testbench-core/laravel/artisan';
    $process = new Process(
        [PHP_BINARY, $artisan, 'route:list', '--json'],
        $repoRoot,
        [
            'TESTBENCH_WORKING_PATH' => $repoRoot,
            'BUILT_FOR_CLOUD_CONSOLE_ENABLED' => $console ? 'true' : 'false',
            'BUILT_FOR_CLOUD_CREDENTIAL_API_ENABLED' => $legacyApi ? 'true' : 'false',
        ],
    );
    $process->mustRun();

    $routes = json_decode($process->getOutput(), true, flags: JSON_THROW_ON_ERROR);
    $gates = [EnsureAdminToken::class, EnsureCredentialAdmin::class, EnsureConsoleSession::class, EnsureDashboardCredential::class];
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
    'console and legacy API enabled' => [true, true, 20],
    'console only' => [true, false, 14],
    'legacy API only' => [false, true, 19],
    'both optional surfaces disabled' => [false, false, 13],
]);
