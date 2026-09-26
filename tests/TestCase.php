<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use ArtisanBuild\BuiltForCloud\StandaloneAccess;
use ArtisanBuild\BuiltForCloud\User;
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

    public function actingAsVersioned(User $user, ?string $guard = null): static
    {
        $user->refresh();

        return $this->actingAs($user, $guard)->withSession([
            StandaloneAccess::SESSION_VERSION_KEY => $user->auth_session_version,
        ]);
    }

    /**
     * @param  Application  $app
     */
    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('auth.providers', []);
        $app['config']->set('auth.guards', []);
        $app['config']->set('cache.default', 'array');
        $app['config']->set('session.driver', 'array');
        $app['config']->set('app.debug', false);

        // The hmac keyring encrypts under the real app key (SEC-V3-08);
        // testbench ships without one, so give every test the key a real
        // install always has. Deterministic on purpose: a fixed key makes
        // key-version fingerprints stable within a run.
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('bfc-test-key-32b', 2)));
        $app['config']->set('built-for-cloud.hmac.audience', 'https://bfc-test-installation.example');

        // Every Built for Cloud app declares a manifest and does not boot
        // without one; tests that need other values set their own.
        $app['config']->set('built-for-cloud.manifest', self::manifestForTests());
    }

    /**
     * A valid manifest for the test app.
     *
     * @return array{name: string, slug: string, description: string, icon: string, product_url: string}
     */
    public static function manifestForTests(): array
    {
        return [
            'name' => 'Test App',
            'slug' => 'test-app',
            'description' => 'The app the package test suite boots.',
            'icon' => 'https://scalpels.app/img/products/transparent/test-app.png',
            'product_url' => 'https://scalpels.app/products/test-app',
        ];
    }
}
