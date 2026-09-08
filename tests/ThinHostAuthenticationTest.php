<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\TestCase as Orchestra;

final class ThinHostAuthenticationTest extends Orchestra
{
    /**
     * @param  Application  $app
     * @return list<class-string>
     */
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
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('thin-host-key-32', 2)));
    }

    protected function defineRoutes($router): void
    {
        require __DIR__.'/Fixtures/ThinHost/routes/web.php';
    }

    public function test_an_auth_artifact_free_host_migrates_and_authenticates_through_the_package(): void
    {
        $this->artisan('migrate')->assertSuccessful();

        $user = User::query()->create([
            'name' => 'Thin Host User',
            'email' => 'thin-host@example.test',
            'password' => Hash::make('thin-host-password'),
        ]);
        $guard = Auth::guard('web');
        $retrieved = $guard->getProvider()->retrieveByCredentials(['email' => $user->email]);

        $this->assertTrue(Schema::hasTable('users'));
        $this->assertSame('web', config('auth.defaults.guard'));
        $this->assertSame(['driver' => 'session', 'provider' => 'users'], config('auth.guards.web'));
        $this->assertSame(User::class, config('auth.providers.users.model'));
        $this->assertInstanceOf(User::class, $retrieved);
        $this->assertTrue($guard->getProvider()->validateCredentials($retrieved, [
            'password' => 'thin-host-password',
        ]));

        $guard->login($user);

        $this->assertTrue($guard->check());
        $this->assertSame((string) $user->getKey(), (string) $guard->id());
        $this->get('/domain')->assertOk()->assertJsonPath('domain', true);
    }
}
