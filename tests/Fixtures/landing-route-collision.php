<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use Illuminate\Foundation\Application;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;
use Orchestra\Testbench\TestCase;

require __DIR__.'/../../vendor/autoload.php';

$mode = $argv[1] ?? '';

if (! in_array($mode, ['early', 'late'], true)) {
    fwrite(STDERR, "Choose an early or late root collision.\n");
    exit(3);
}

$_SERVER['BFC_LANDING_COLLISION'] = $mode;

final class BfcStarterRootProvider extends ServiceProvider
{
    public function boot(Router $router): void
    {
        $router->get('/', static fn (): string => 'starter-root')->name('starter.root');
    }
}

$case = new class('testProbe') extends TestCase
{
    /** @return list<class-string> */
    protected function getPackageProviders($app): array
    {
        return ($_SERVER['BFC_LANDING_COLLISION'] ?? '') === 'early'
            ? [BfcStarterRootProvider::class, BuiltForCloudServiceProvider::class]
            : [BuiltForCloudServiceProvider::class, BfcStarterRootProvider::class];
    }

    /** @param Application $app */
    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('auth.guards', []);
        $app['config']->set('auth.providers', []);
        $app['config']->set('built-for-cloud.surfaces.data_migrations', false);
        $app['config']->set('built-for-cloud.ui.landing_page', true);
        $app['config']->set('built-for-cloud.manifest', [
            'name' => 'Collision Test App',
            'slug' => 'collision-test-app',
            'description' => 'A test-created collision fixture.',
            'icon' => 'https://assets.example.test/collision.svg',
            'product_url' => 'https://scalpels.app/products/collision-test-app',
        ]);
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('collision-key-16', 2)));
    }

    public function bootProbe(): void
    {
        parent::setUp();
    }

    public function test_probe(): void {}
};

try {
    $case->bootProbe();
} catch (RuntimeException $exception) {
    $expected = $mode === 'early'
        ? 'remove the host root route before enabling it'
        : 'reserved by the built-for-cloud landing page';

    if (str_contains($exception->getMessage(), $expected)) {
        fwrite(STDOUT, $exception->getMessage().PHP_EOL);
        exit(0);
    }

    fwrite(STDERR, $exception::class.': '.$exception->getMessage().PHP_EOL);
    exit(2);
}

fwrite(STDERR, "The {$mode} starter root collision was not refused.\n");
exit(1);
