<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use Illuminate\Foundation\Application;
use Orchestra\Testbench\TestCase;

require __DIR__.'/../../vendor/autoload.php';

$collision = $argv[1] ?? '';

$case = new class('testProbe') extends TestCase
{
    /** @return list<class-string> */
    protected function getPackageProviders($app): array
    {
        return [BuiltForCloudServiceProvider::class];
    }

    /** @param Application $app */
    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('auth.defaults.guard', 'web');
        $app['config']->set('auth.guards', []);
        $app['config']->set('auth.providers', []);
        $app['config']->set('built-for-cloud.surfaces.data_migrations', false);
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('route-probe-key!', 2)));
    }

    protected function defineRoutes($router): void
    {
        $collision = $_SERVER['BFC_ROUTE_COLLISION'] ?? '';

        if ($collision === 'name') {
            $router->get('/host-login', static fn (): string => 'host')
                ->name('bfc.login');
        } elseif ($collision === 'pair') {
            $router->get('/bfc/login', static fn (): string => 'host')
                ->name('host.login');
        } elseif ($collision === 'middleware') {
            foreach ($router->getRoutes() as $route) {
                if (in_array($route->getName(), ['bfc.login', 'bfc.login.store'], true)) {
                    $route->withoutMiddleware('bfc.standalone');
                }
            }
        }
    }

    public function bootProbe(): void
    {
        parent::setUp();
    }

    public function test_probe(): void {}
};

if (! in_array($collision, ['name', 'pair', 'middleware'], true)) {
    fwrite(STDERR, "Unknown collision probe.\n");
    exit(2);
}

$_SERVER['BFC_ROUTE_COLLISION'] = $collision;

try {
    $case->bootProbe();
} catch (RuntimeException $exception) {
    if (str_contains($exception->getMessage(), 'reserved by built-for-cloud standalone authentication')) {
        fwrite(STDOUT, $exception->getMessage().PHP_EOL);
        exit(0);
    }

    fwrite(STDERR, $exception::class.': '.$exception->getMessage().PHP_EOL);
    exit(3);
}

fwrite(STDERR, "The colliding thin host booted unexpectedly.\n");
exit(1);
