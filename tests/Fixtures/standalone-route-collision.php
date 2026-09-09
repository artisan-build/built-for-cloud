<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureStandaloneAuthority;
use Illuminate\Foundation\Application;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;
use Orchestra\Testbench\TestCase;

require __DIR__.'/../../vendor/autoload.php';

$collision = $argv[1] ?? '';

final class BfcLateRouteCollisionState
{
    public static int $hostRuns = 0;
}

final class BfcLateRouteCollisionProvider extends ServiceProvider
{
    public function boot(Router $router): void
    {
        $collision = $_SERVER['BFC_ROUTE_COLLISION'] ?? '';

        if (! str_starts_with($collision, 'late-')) {
            return;
        }

        $this->app->booted(static function () use ($router, $collision): void {
            $uri = $collision === 'late-name' ? '/host-login' : '/bfc/login';
            $name = $collision === 'late-name' ? 'bfc.login' : 'host.login';
            $router->get($uri, static function (): string {
                BfcLateRouteCollisionState::$hostRuns++;

                return 'late-host-login';
            })->name($name);
        });
    }
}

$case = new class('testProbe') extends TestCase
{
    /** @return list<class-string> */
    protected function getPackageProviders($app): array
    {
        return [BuiltForCloudServiceProvider::class, BfcLateRouteCollisionProvider::class];
    }

    /** @param Application $app */
    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('auth.defaults.guard', 'web');
        $app['config']->set('auth.guards', []);
        $app['config']->set('auth.providers', []);
        $app['config']->set('built-for-cloud.surfaces.data_migrations', false);
        $app['config']->set('app.debug', false);
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
                    $route->withoutMiddleware(EnsureStandaloneAuthority::class);
                }
            }
        }
    }

    /** @return array{status: int, host_runs: int}|null */
    public function bootProbe(): ?array
    {
        parent::setUp();

        $collision = $_SERVER['BFC_ROUTE_COLLISION'] ?? '';

        if (! str_starts_with($collision, 'late-')) {
            return null;
        }

        $path = $collision === 'late-name' ? '/host-login' : '/bfc/login';
        $response = $this->get($path);

        return [
            'status' => $response->getStatusCode(),
            'host_runs' => BfcLateRouteCollisionState::$hostRuns,
        ];
    }

    public function test_probe(): void {}
};

if (! in_array($collision, ['name', 'pair', 'middleware', 'late-name', 'late-pair'], true)) {
    fwrite(STDERR, "Unknown collision probe.\n");
    exit(2);
}

$_SERVER['BFC_ROUTE_COLLISION'] = $collision;

try {
    $result = $case->bootProbe();
} catch (RuntimeException $exception) {
    if (str_contains($exception->getMessage(), 'reserved by built-for-cloud standalone authentication')) {
        fwrite(STDOUT, $exception->getMessage().PHP_EOL);
        exit(0);
    }

    fwrite(STDERR, $exception::class.': '.$exception->getMessage().PHP_EOL);
    exit(3);
}

if (str_starts_with($collision, 'late-')
    && $result === ['status' => 500, 'host_runs' => 0]) {
    fwrite(STDOUT, "The late route collision was refused before the host handler.\n");
    exit(0);
}

fwrite(STDERR, "The colliding thin host booted unexpectedly.\n");
exit(1);
