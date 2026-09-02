<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use Illuminate\Foundation\Application;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    /**
     * @param  Application  $app
     * @return list<class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [BuiltForCloudServiceProvider::class];
    }

    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/database/migrations');
    }

    /**
     * @param  Application  $app
     */
    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('auth.providers.users.model', Fixtures\User::class);

        $app['config']->set('database.connections.pgsql_testing', [
            'driver' => 'pgsql',
            'host' => $this->environment('PGSQL_TESTING_HOST', '127.0.0.1'),
            'port' => $this->environment('PGSQL_TESTING_PORT', '5432'),
            'database' => $this->environment('PGSQL_TESTING_DATABASE', 'bfc_testing'),
            'username' => $this->environment('PGSQL_TESTING_USERNAME', 'postgres'),
            'password' => $this->environment('PGSQL_TESTING_PASSWORD', 'postgres'),
            'charset' => 'utf8',
            'prefix' => '',
            'prefix_indexes' => true,
            'search_path' => 'public',
            'sslmode' => 'prefer',
        ]);

        // The Console is OFF by default in a consuming app (it gates the
        // delegated guard's injection, and with it the delegated
        // behaviour of the package's session gates). The package's own
        // suite is the deployment that HAS it, so it is enabled here —
        // ConsoleDisabledTest turns it back off to drive the other side.
        $app['config']->set('built-for-cloud.console.enabled', true);

        // The hmac keyring encrypts under the real app key (SEC-V3-08);
        // testbench ships without one, so give every test the key a real
        // install always has. Deterministic on purpose: a fixed key makes
        // key-version fingerprints stable within a run.
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('bfc-test-key-32b', 2)));
    }

    private function environment(string $name, string $default): string
    {
        $value = getenv($name);

        return $value === false ? $default : $value;
    }
}
