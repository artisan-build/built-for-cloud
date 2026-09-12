<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Http\Middleware\PackageMiddlewareProbe;
use ArtisanBuild\BuiltForCloud\StandaloneRouteOwnership;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use Symfony\Component\Process\Process;

require_once __DIR__.'/Fixtures/PackageMiddlewareProbe.php';

it('refuses standalone authentication gate resolution attacks at boot', function (string $vector): void {
    $process = new Process([PHP_BINARY, __DIR__.'/Fixtures/standalone-auth.php', $vector, 'boot']);
    $process->run();

    expect($process->getExitCode())->toBe(0, $process->getOutput().$process->getErrorOutput())
        ->and($process->getOutput())->toContain('standalone-auth-gate-boot-refused');
})->with([
    'FQCN alias' => 'fqcn-alias',
    'FQCN group' => 'fqcn-group',
    'FQCN exclusion' => 'fqcn-exclusion',
    'package alias exclusion' => 'alias-exclusion',
]);

it('refuses every standalone authentication route before effects or disclosure after boot', function (string $vector): void {
    $process = new Process([PHP_BINARY, __DIR__.'/Fixtures/standalone-auth.php', $vector, 'match']);
    $process->run();

    expect($process->getExitCode())->toBe(0, $process->getOutput().$process->getErrorOutput())
        ->and($process->getOutput())->toContain('standalone-auth-gate-match-refused-15');
})->with([
    'FQCN alias' => 'fqcn-alias',
    'FQCN group' => 'fqcn-group',
    'FQCN exclusion' => 'fqcn-exclusion',
    'package alias exclusion' => 'alias-exclusion',
]);

it('refuses every standalone authentication route from a real compiled route collection', function (): void {
    $payload = sys_get_temp_dir().'/bfc-standalone-auth-route-cache-'.bin2hex(random_bytes(8)).'.php';

    try {
        $generate = new Process([PHP_BINARY, __DIR__.'/Fixtures/standalone-route-cache.php', 'generate', $payload]);
        $generate->mustRun();

        $load = new Process([PHP_BINARY, __DIR__.'/Fixtures/standalone-auth-route-cache.php', $payload]);
        $load->run();

        expect($load->getExitCode())->toBe(0, $load->getOutput().$load->getErrorOutput())
            ->and($load->getOutput())->toContain('standalone-auth-route-cache-refused-15');
    } finally {
        @unlink($payload);
    }
});

it('recomputes poisoned authentication middleware for every uncached and compiled route', function (string $vector): void {
    $uncached = new Process([PHP_BINARY, __DIR__.'/Fixtures/standalone-auth.php', $vector, 'match']);
    $uncached->run();

    expect($uncached->getExitCode())->toBe(0, $uncached->getOutput().$uncached->getErrorOutput())
        ->and($uncached->getOutput())->toContain("standalone-auth-gate-{$vector}-refused-15");

    $payload = sys_get_temp_dir().'/bfc-standalone-auth-memo-cache-'.bin2hex(random_bytes(8)).'.php';

    try {
        $generate = new Process([PHP_BINARY, __DIR__.'/Fixtures/standalone-route-cache.php', 'generate', $payload]);
        $generate->mustRun();

        $compiled = new Process([PHP_BINARY, __DIR__.'/Fixtures/standalone-auth-route-cache.php', $payload, $vector]);
        $compiled->run();

        expect($compiled->getExitCode())->toBe(0, $compiled->getOutput().$compiled->getErrorOutput())
            ->and($compiled->getOutput())->toContain("standalone-auth-route-cache-{$vector}-refused-15");
    } finally {
        @unlink($payload);
    }
})->with([
    'setAction and restore' => 'memo-set-action',
    'public computedMiddleware property' => 'memo-property',
]);

it('pins an unknown package-namespace middleware without a hardcoded gate list', function (string $vector): void {
    /** @var Router $router */
    $router = app('router');
    $route = $router->getRoutes()->getByName('bfc.members.index');

    if (! $route instanceof Route) {
        throw new RuntimeException('The standalone members route is unavailable.');
    }

    $route->middleware(PackageMiddlewareProbe::class);
    $inventory = StandaloneRouteOwnership::packageMiddlewareInventory([$route]);

    if ($vector === 'control') {
        StandaloneRouteOwnership::assertPackageMiddlewareOwned($router, $inventory);

        expect($inventory[0]['middleware'])->toContain(PackageMiddlewareProbe::class);

        return;
    }

    match ($vector) {
        'alias' => $router->aliasMiddleware(PackageMiddlewareProbe::class, SubstituteBindings::class),
        'group' => $router->middlewareGroup(PackageMiddlewareProbe::class, [SubstituteBindings::class]),
        'exclusion' => $route->withoutMiddleware(PackageMiddlewareProbe::class),
    };

    expect(fn () => StandaloneRouteOwnership::assertPackageMiddlewareOwned($router, $inventory))
        ->toThrow(RuntimeException::class, 'must retain its built-for-cloud package middleware');
})->with([
    'clean control' => 'control',
    'FQCN alias' => 'alias',
    'FQCN group' => 'group',
    'FQCN exclusion' => 'exclusion',
]);
