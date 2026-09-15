<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\BuiltForCloud;
use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureContractMajor;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Tests\Support\ContractMajorRouteCacheProbe;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Contracts\Auth\Middleware\AuthenticatesRequests;
use Illuminate\Foundation\Application;
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
            $app['config']->set('auth.guards', []);
            $app['config']->set('auth.providers', []);
            $app['config']->set('built-for-cloud.surfaces.data_migrations', false);
            $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('v', 32)));
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
                        'BFC_CONTRACT_MAJOR_ROUTE_CACHE' => 'true',
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
                        && str_contains($contents, 'bfc-harness.contract-major-cache.explicit')
                        && str_contains($contents, 'bfc-harness.contract-major-cache.renamed')
                        && str_contains($contents, 'bfc-harness.contract-major-cache.default'),
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
        $app['config']->set('auth.defaults.guard', 'web');
        $app['config']->set('auth.guards', [
            'web' => ['driver' => 'session', 'provider' => 'users'],
            'bfc' => ['driver' => 'bfc', 'provider' => null],
            'contract-api' => ['driver' => 'bfc', 'provider' => null],
            'contract-default' => ['driver' => 'bfc', 'provider' => null],
        ]);
        $app['config']->set('auth.providers.users', ['driver' => 'eloquent', 'model' => User::class]);
        $app['config']->set('built-for-cloud.surfaces.data_migrations', false);
        $app['config']->set('cache.default', 'array');
        $app['config']->set('app.debug', false);
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('w', 32)));
    }

    public function load(string $payload): bool
    {
        parent::setUp();
        $this->artisan('migrate:fresh', ['--force' => true])->run();
        $this->app['config']->set('auth.defaults.guard', 'contract-default');

        require $payload;

        /** @var Router $router */
        $router = $this->app['router'];

        if ($router->getRoutes()::class !== CompiledRouteCollection::class) {
            fwrite(STDERR, 'collection:'.$router->getRoutes()::class.PHP_EOL);

            return false;
        }

        $secret = 'contract-major-route-cache-secret';
        $credential = Credential::factory()->create([
            'kind' => CredentialKind::Bearer,
            'purpose' => CredentialPurpose::Consumption,
            'subject_type' => SubjectType::ExternalConsumer,
            'subject_ref' => 'contract-major-route-cache-consumer',
            'secret_hash' => hash('sha256', $secret),
            'status' => CredentialStatus::Active,
        ]);
        $routes = [
            'bfc-harness.contract-major-cache.explicit' => '/_bfc-harness/contract-major-cache/explicit',
            'bfc-harness.contract-major-cache.renamed' => '/_bfc-harness/contract-major-cache/renamed',
            'bfc-harness.contract-major-cache.default' => '/_bfc-harness/contract-major-cache/default',
        ];

        foreach ($routes as $name => $uri) {
            $response = $this->withHeader('Authorization', 'Bearer '.$secret)->postJson($uri);

            if ($response->getStatusCode() !== 400
                || $response->json() !== [
                    'error' => 'missing_contract_major',
                    'supported_contract_major' => BuiltForCloud::API_VERSION,
                ]
                || $response->headers->get('Cache-Control') !== 'no-store, private') {
                fwrite(STDERR, 'refusal:'.$name.':'.$response->getStatusCode().PHP_EOL);

                return false;
            }

            $route = $router->getRoutes()->getByName($name);

            if ($route === null) {
                fwrite(STDERR, 'route-missing:'.$name.PHP_EOL);

                return false;
            }

            $resolved = $router->gatherRouteMiddleware($route);
            $admission = array_search(EnsureContractMajor::class, $resolved, true);
            $authentication = null;

            foreach ($resolved as $index => $middleware) {
                [$class] = explode(':', $middleware, 2);

                if (is_a($class, AuthenticatesRequests::class, true)) {
                    $authentication = $index;
                    break;
                }
            }

            if (! is_int($admission) || ! is_int($authentication) || $admission >= $authentication) {
                fwrite(STDERR, 'order:'.$name.PHP_EOL);

                return false;
            }
        }

        return $credential->refresh()->last_used_at === null
            && ContractMajorRouteCacheProbe::$runs === 0;
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
    fwrite(STDERR, "The compiled contract-major route table failed its admission contract.\n");
    exit(1);
}

fwrite(STDOUT, "contract-major-route-cache-ok\n");
