<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Routing\CompiledRouteCollection;
use Illuminate\Routing\Router;
use Orchestra\Testbench\TestCase;
use Symfony\Component\Process\Process;

require __DIR__.'/../../vendor/autoload.php';

$mode = $argv[1] ?? '';

if ($mode === 'generate') {
    $destination = $argv[2] ?? '';

    if ($destination === '') {
        fwrite(STDERR, "A destination path is required.\n");
        exit(2);
    }

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
            $app['config']->set('built-for-cloud.manifest', ArtisanBuild\BuiltForCloud\Tests\TestCase::manifestForTests());
            $app['config']->set('auth.guards', []);
            $app['config']->set('auth.providers', []);
            $app['config']->set('built-for-cloud.surfaces.data_migrations', false);
            $app['config']->set('cache.default', 'array');
            $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('m', 32)));
        }

        /** @return array{exit: int, copied: bool, contains: bool} */
        public function generate(string $destination): array
        {
            parent::setUp();

            $cachePath = $this->app->getCachedRoutesPath();
            $cacheDir = dirname($cachePath);
            $before = is_dir($cacheDir) ? scandir($cacheDir) : [];

            try {
                @unlink($cachePath);

                $repoRoot = dirname(__DIR__, 2);
                $artisan = $repoRoot.'/vendor/orchestra/testbench-core/laravel/artisan';
                $process = new Process(
                    [PHP_BINARY, $artisan, 'route:cache'],
                    $repoRoot,
                    [
                        'TESTBENCH_WORKING_PATH' => $repoRoot,
                        'BFC_MCP_METADATA_ROUTE_CACHE' => 'true',
                    ],
                );
                $process->setTimeout(60);
                $exitCode = $process->run();

                if ($exitCode !== 0 || ! is_file($cachePath)) {
                    return ['exit' => $exitCode, 'copied' => false, 'contains' => false];
                }

                $contents = file_get_contents($cachePath);

                return [
                    'exit' => $exitCode,
                    'copied' => copy($cachePath, $destination),
                    'contains' => is_string($contents)
                        && str_contains($contents, 'bfc-harness.mcp-cache.parameterized')
                        && str_contains($contents, 'bfc-harness.mcp-cache.plain')
                        && str_contains($contents, 'bfc-harness.mcp-cache.unguarded'),
                ];
            } finally {
                @unlink($cachePath);

                $after = is_dir($cacheDir) ? scandir($cacheDir) : [];

                foreach (array_diff($after, $before) as $created) {
                    if (is_file($cacheDir.'/'.$created)) {
                        @unlink($cacheDir.'/'.$created);
                    }
                }
            }
        }

        public function test_probe(): void {}
    };

    try {
        $result = $case->generate($destination);
        fwrite(STDOUT, json_encode($result, JSON_THROW_ON_ERROR).PHP_EOL);
        exit($result['exit'] === 0 && $result['copied'] && $result['contains'] ? 0 : 1);
    } catch (Throwable $exception) {
        fwrite(STDERR, $exception::class.': '.$exception->getMessage().PHP_EOL);
        exit(1);
    }
}

if ($mode !== 'load') {
    fwrite(STDERR, "Unknown route-cache probe mode.\n");
    exit(2);
}

$payload = $argv[2] ?? '';

if (! is_file($payload)) {
    fwrite(STDERR, "The generated route cache is unavailable.\n");
    exit(2);
}

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
        $app['config']->set('built-for-cloud.manifest', ArtisanBuild\BuiltForCloud\Tests\TestCase::manifestForTests());
        $app['config']->set('auth.guards', []);
        $app['config']->set('auth.providers', []);
        $app['config']->set('built-for-cloud.surfaces.data_migrations', false);
        $app['config']->set('cache.default', 'array');
        $app['config']->set('app.debug', false);
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('n', 32)));
    }

    public function load(string $payload): bool
    {
        parent::setUp();
        $this->artisan('migrate:fresh', ['--force' => true])->run();

        require $payload;

        /** @var Router $router */
        $router = $this->app['router'];

        if ($router->getRoutes()::class !== CompiledRouteCollection::class) {
            fwrite(STDERR, 'collection:'.$router->getRoutes()::class.PHP_EOL);

            return false;
        }

        $this->withoutExceptionHandling();

        $cases = [
            '/_bfc-harness/mcp-cache/parameterized' => true,
            '/_bfc-harness/mcp-cache/plain' => true,
            '/_bfc-harness/mcp-cache/unguarded' => false,
        ];

        foreach ($cases as $path => $expected) {
            $this->app['config']->set('built-for-cloud.mcp.path', $path);
            $this->app['config']->set('built-for-cloud.mcp.delegated', true);

            $response = $this->getJson('/bfc/meta');
            $capabilities = $response->json('capabilities');

            if (! is_array($capabilities)
                || in_array('mcp-delegated', $capabilities, true) !== $expected) {
                $matched = $router->getRoutes()->match(Request::create('http://localhost'.$path, 'POST'));
                fwrite(STDERR, 'capability:'.$path.':'.json_encode([
                    'name' => $matched->getName(),
                    'middleware' => $router->gatherRouteMiddleware($matched),
                    'status' => $response->getStatusCode(),
                    'body' => $response->getContent(),
                    'capabilities' => $capabilities,
                ], JSON_THROW_ON_ERROR).PHP_EOL);

                return false;
            }
        }

        return true;
    }

    public function test_probe(): void {}
};

try {
    $valid = $case->load($payload);
} catch (Throwable $exception) {
    fwrite(STDERR, $exception::class.': '.$exception->getMessage().PHP_EOL);
    exit(1);
}

if (! $valid) {
    fwrite(STDERR, "The compiled MCP route table failed its metadata contract.\n");
    exit(1);
}

fwrite(STDOUT, "mcp-metadata-route-cache-ok\n");
