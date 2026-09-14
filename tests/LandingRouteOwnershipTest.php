<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\LandingPageRegistrar;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Route;
use Symfony\Component\Process\Process;

it('mounts no package root and requires no manifest while landing is disabled', function (): void {
    expect(config('built-for-cloud.manifest'))->toBe([
        'name' => null,
        'slug' => null,
        'description' => null,
        'icon' => null,
        'product_url' => null,
    ])->and(Route::getRoutes()->getByName('bfc.landing'))->toBeNull();

    Route::get('/', static fn (): string => 'test-created-host-root')->name('test.host-root');
    $this->get('/')->assertOk()->assertSee('test-created-host-root');
});

it('refuses a thin host starter root regardless of registration order', function (string $mode, string $message): void {
    $process = new Process([PHP_BINARY, __DIR__.'/Fixtures/landing-route-collision.php', $mode]);
    $process->run();

    expect($process->getExitCode())->toBe(0, $process->getOutput().$process->getErrorOutput())
        ->and($process->getOutput())->toContain($message);
})->with([
    'host first' => ['early', 'remove the host root route before enabling it'],
    'package first' => ['late', 'reserved by the built-for-cloud landing page'],
]);

it('validates the manifest when landing is enabled', function (): void {
    config(['built-for-cloud.ui.landing_page' => true]);

    expect(fn () => app(LandingPageRegistrar::class)->mount(app(Router::class)))
        ->toThrow(RuntimeException::class, 'landing manifest');
});
