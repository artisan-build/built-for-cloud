<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureAdminToken;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureConsoleSession;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureDashboardCredential;
use ArtisanBuild\BuiltForCloud\Ownership;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Routing\CompiledRouteCollection;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Notification;
use Orchestra\Testbench\TestCase;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Process\Process;

require __DIR__.'/../../vendor/autoload.php';

$mode = $argv[1] ?? '';

final class CachedHostileOperatorGate
{
    public static int $runs = 0;

    /** @param Closure(Request): Response $next */
    public function handle(Request $request, Closure $next): Response
    {
        self::$runs++;

        return $next($request);
    }
}

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
            $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('o', 32)));
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
                        'BUILT_FOR_CLOUD_CONSOLE_ENABLED' => 'true',
                        'BUILT_FOR_CLOUD_CREDENTIAL_API_ENABLED' => 'true',
                    ],
                );
                $exitCode = $process->run();

                if ($exitCode !== 0 || ! is_file($cachePath)) {
                    return ['exit' => $exitCode, 'copied' => false, 'contains' => false];
                }

                $contents = file_get_contents($cachePath);

                return [
                    'exit' => $exitCode,
                    'copied' => copy($cachePath, $destination),
                    'contains' => is_string($contents)
                        && str_contains($contents, 'bfc/ownership/release')
                        && str_contains($contents, 'bfc/console/vitals')
                        && str_contains($contents, 'bfc/console/chrome.js')
                        && str_contains($contents, 'api/credentials'),
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
        $app['config']->set('auth.guards.web', ['driver' => 'session', 'provider' => 'users']);
        $app['config']->set('auth.guards.bfc-console', ['driver' => 'bfc-console-session']);
        $app['config']->set('auth.providers.users', ['driver' => 'eloquent', 'model' => User::class]);
        $app['config']->set('built-for-cloud.console.enabled', true);
        $app['config']->set('built-for-cloud.credential_api.enabled', true);
        $app['config']->set('built-for-cloud.surfaces.data_migrations', false);
        $app['config']->set('cache.default', 'array');
        $app['config']->set('app.debug', false);
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('c', 32)));
    }

    public function load(string $payload): bool
    {
        parent::setUp();
        $this->artisan('migrate:fresh', ['--force' => true])->run();
        Mail::fake();
        Notification::fake();

        require $payload;

        /** @var Router $router */
        $router = $this->app['router'];

        if ($router->getRoutes()::class !== CompiledRouteCollection::class) {
            fwrite(STDERR, 'collection:'.$router->getRoutes()::class.PHP_EOL);

            return false;
        }

        foreach ([EnsureAdminToken::class, EnsureCredentialAdmin::class, EnsureConsoleSession::class, EnsureDashboardCredential::class] as $gate) {
            $router->aliasMiddleware($gate, CachedHostileOperatorGate::class);
        }

        $owner = ApiToken::factory()->create([
            'name' => 'cache-owner',
            'abilities' => [Scope::Admin->value],
        ]);
        $ownership = Ownership::query()->create(['owner_token_id' => $owner->getKey()]);
        $tokenLookups = 0;

        DB::listen(static function (QueryExecuted $query) use (&$tokenLookups): void {
            $sql = strtolower(ltrim($query->sql));

            if (str_starts_with($sql, 'select') && str_contains($sql, 'api_tokens')) {
                $tokenLookups++;
            }
        });

        $routes = [
            ['POST', '/bfc/ownership/release'],
            ['POST', '/bfc/ownership/cancel-transfer'],
            ['POST', '/bfc/onboarding/issue'],
            ['GET', '/bfc/credentials'],
            ['POST', '/bfc/credentials'],
            ['DELETE', '/bfc/credentials/missing'],
            ['POST', '/bfc/credentials/missing/rotate'],
            ['POST', '/bfc/credentials/missing/activate'],
            ['POST', '/bfc/console/re-key'],
            ['POST', '/bfc/console/keys/missing/retire'],
            ['GET', '/bfc/console/vitals'],
            ['GET', '/bfc/console/chrome.js'],
            ['POST', '/bfc/subjects/offboard'],
            ['GET', '/api/credentials'],
            ['GET', '/api/credentials/client-observations'],
            ['POST', '/api/credentials'],
            ['DELETE', '/api/credentials/id/missing'],
            ['POST', '/api/credentials/id/missing/rotate'],
            ['DELETE', '/api/credentials/missing'],
        ];
        $refusals = 0;
        $this->withoutExceptionHandling();

        foreach ($routes as [$method, $uri]) {
            try {
                $this->call($method, $uri);
            } catch (RuntimeException $exception) {
                if (! str_contains($exception->getMessage(), 'must retain its built-for-cloud operator gate')) {
                    fwrite(STDERR, 'unexpected-refusal:'.$exception->getMessage().PHP_EOL);

                    return false;
                }

                $refusals++;
            }
        }

        return $refusals === count($routes)
            && CachedHostileOperatorGate::$runs === 0
            && $tokenLookups === 0
            && $ownership->refresh()->pending_claim_id === null
            && Credential::query()->count() === 0;
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
    fwrite(STDERR, "The compiled operator route table failed its ownership contract.\n");
    exit(1);
}

fwrite(STDOUT, "operator-route-cache-ok\n");
