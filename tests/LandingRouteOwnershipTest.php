<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\LandingPageRegistrar;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Route;
use Symfony\Component\Process\Process;

it('mounts the landing page at the root of every app', function (): void {
    $landing = Route::getRoutes()->getByName('bfc.landing');

    expect($landing)->not->toBeNull()
        ->and($landing?->uri())->toBe('/');

    $this->get('/')->assertOk()->assertSeeHtml('data-testid="landing"')->assertSee('Test App');
});

it('refuses a thin host starter root regardless of registration order', function (string $mode, string $message): void {
    $process = new Process([PHP_BINARY, __DIR__.'/Fixtures/landing-route-collision.php', $mode]);
    $process->run();

    expect($process->getExitCode())->toBe(0, $process->getOutput().$process->getErrorOutput())
        ->and($process->getOutput())->toContain($message);
})->with([
    'host first' => ['early', 'remove the host root route'],
    'package first' => ['late', 'reserved by the built-for-cloud landing page'],
]);

it('refuses to mount the landing page without a manifest', function (): void {
    config(['built-for-cloud.manifest' => [
        'name' => null,
        'slug' => null,
        'description' => null,
        'icon' => null,
        'product_url' => null,
    ]]);

    expect(fn () => app(LandingPageRegistrar::class)->mount(new Router(app('events'), app())))
        ->toThrow(RuntimeException::class, 'landing manifest');
});
