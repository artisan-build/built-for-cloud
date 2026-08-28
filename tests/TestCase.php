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

        // The hmac keyring encrypts under the real app key (SEC-V3-08);
        // testbench ships without one, so give every test the key a real
        // install always has. Deterministic on purpose: a fixed key makes
        // key-version fingerprints stable within a run.
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('bfc-test-key-32b', 2)));
    }
}
