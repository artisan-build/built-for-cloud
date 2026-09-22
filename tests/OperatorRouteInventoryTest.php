<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Http\Controllers\BoundHmacCutovers;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureDashboardCredential;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use Symfony\Component\Process\Process;

it('derives the complete operator route inventory whatever the retired console flag said', function (bool $console, int $expected): void {
    // `BUILT_FOR_CLOUD_CONSOLE_ENABLED` is retired: the flag no longer
    // exists, and both rows of the dataset prove an environment still
    // carrying it boots the SAME route inventory as one without it.
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
    $gates = [EnsureCredentialAdmin::class, EnsureDashboardCredential::class];
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
    $cutoverRoutes = [];

    foreach ($operatorRoutes as $route) {
        if (! str_starts_with($route['uri'], 'bfc/hmac-cutovers/')) {
            continue;
        }

        $cutoverRoutes[$route['uri']] = [
            'method' => $route['method'],
            'action' => $route['action'],
            'gate' => array_values(array_filter(
                $route['middleware'],
                static fn (string $middleware): bool => str_starts_with($middleware, EnsureCredentialAdmin::class.':'),
            )),
        ];
    }

    expect($operatorRoutes)->toHaveCount($expected)
        ->and($cutoverRoutes)->toBe([
            'bfc/hmac-cutovers/activate' => [
                'method' => 'POST',
                'action' => BoundHmacCutovers::class.'@activate',
                'gate' => [EnsureCredentialAdmin::class.':'.OperatorAbility::CredentialRotate->value],
            ],
            'bfc/hmac-cutovers/status' => [
                'method' => 'POST',
                'action' => BoundHmacCutovers::class.'@status',
                'gate' => [EnsureCredentialAdmin::class.':'.OperatorAbility::CredentialRotate->value],
            ],
        ]);
})->with([
    'flag set true' => [true, 15],
    'flag set false' => [false, 15],
]);
