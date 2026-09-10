<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\Database\Factories\CredentialFactory;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAuthenticated;
use ArtisanBuild\BuiltForCloud\Invitation;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Routing\CompiledRouteCollection;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Hash;
use Orchestra\Testbench\TestCase;
use Symfony\Component\HttpFoundation\Response;

require __DIR__.'/../../vendor/autoload.php';

$payload = $argv[1] ?? '';

if (! is_file($payload)) {
    fwrite(STDERR, "The generated route cache is unavailable.\n");
    exit(2);
}

final class BfcStandaloneAuthCacheState
{
    /** @var list<string> */
    public static array $paths = [];
}

final class BfcStandaloneAuthCachePassThrough
{
    /** @param Closure(Request): Response $next */
    public function handle(Request $request, Closure $next): Response
    {
        BfcStandaloneAuthCacheState::$paths[] = $request->path();

        return $next($request);
    }
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
        $app['config']->set('cache.default', 'array');
        $app['config']->set('session.driver', 'array');
        $app['config']->set('built-for-cloud.surfaces.data_migrations', false);
        $app['config']->set('app.debug', false);
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('h', 32)));
    }

    public function runProbe(string $payload): bool
    {
        parent::setUp();
        $this->artisan('migrate:fresh', ['--force' => true])->run();
        require $payload;

        /** @var Router $router */
        $router = $this->app['router'];

        if (! $router->getRoutes() instanceof CompiledRouteCollection) {
            return false;
        }

        $routes = array_values(array_filter(
            $router->getRoutes()->getRoutes(),
            static fn (Route $route): bool => in_array(EnsureUserIsAuthenticated::class, $route->middleware(), true),
        ));

        if (count($routes) !== 11) {
            fwrite(STDERR, 'compiled-auth-route-count-'.count($routes).PHP_EOL);

            return false;
        }

        $member = User::query()->create([
            'name' => 'Compiled Authentication Gate Member',
            'email' => 'compiled-auth-gate-member@example.test',
            'password' => Hash::make('compiled auth gate password'),
        ]);
        $member->forceFill([
            'role' => UserRole::Member->value,
            'status' => 'active',
            'email_verified_at' => now(),
            'original_contact_email' => $member->email,
        ])->save();
        $credential = CredentialFactory::new()->forUser((string) $member->getKey())->create();
        $credentialCount = Credential::query()->count();
        $router->aliasMiddleware(EnsureUserIsAuthenticated::class, BfcStandaloneAuthCachePassThrough::class);

        foreach ($routes as $route) {
            $path = '/'.str_replace(
                ['{user}', '{session}', '{id}'],
                [(string) $member->getKey(), 'compiled-auth-gate-session', (string) $credential->getKey()],
                $route->uri(),
            );
            $response = $this->call($route->methods()[0], $path, [
                'email' => 'new-compiled-auth-gate-member@example.test',
                'role' => UserRole::Admin->value,
                'name' => 'compiled-auth-gate-created',
                'password' => 'not-used-before-refusal',
            ]);

            if ($response->getStatusCode() !== 500
                || str_contains($response->getContent(), (string) $member->email)) {
                fwrite(STDERR, "compiled-auth-route-served-{$route->uri()}-{$response->getStatusCode()}".PHP_EOL);

                return false;
            }
        }

        return BfcStandaloneAuthCacheState::$paths === []
            && Invitation::query()->count() === 0
            && Credential::query()->count() === $credentialCount
            && $member->refresh()->role === UserRole::Member->value
            && $member->status === 'active';
    }

    public function test_probe(): void {}
};

try {
    $valid = $case->runProbe($payload);
} catch (Throwable $exception) {
    fwrite(STDERR, $exception::class.': '.$exception->getMessage().PHP_EOL);
    exit(1);
}

if (! $valid) {
    fwrite(STDERR, "The compiled standalone authentication gate probe failed.\n");
    exit(1);
}

fwrite(STDOUT, "standalone-auth-route-cache-refused-11\n");
