<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\Console\ConsoleGuardConfiguration;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\User;
use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Foundation\Application;

/**
 * The other half of FLEET-C-14: the package injects its guard config, it
 * does not OWN it. An app that has already defined `bfc-console` — or
 * the provider behind it — keeps exactly what it wrote, because config
 * an app authored is that app's decision and replacing it at boot would
 * be a package quietly deciding who a deployment's operators are.
 *
 * PHPUnit-style on purpose: the app's own entries must exist BEFORE the
 * package provider registers, and per-test config attributes are far too
 * late for that.
 */
final class ConsoleGuardNotOverwrittenTest extends TestCase
{
    /**
     * @param  Application  $app
     */
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('auth.guards.'.ConsoleGuardConfiguration::GUARD, [
            'driver' => 'session',
            'provider' => 'users',
        ]);

        $app['config']->set('auth.providers.bfc-console-actors', [
            'driver' => 'eloquent',
            'model' => User::class,
        ]);
    }

    public function test_it_does_not_overwrite_a_guard_the_app_already_defined(): void
    {
        $this->assertSame(
            ['driver' => 'session', 'provider' => 'users'],
            config('auth.guards.'.ConsoleGuardConfiguration::GUARD),
        );

        $this->assertSame(
            ['driver' => 'eloquent', 'model' => User::class],
            config('auth.providers.bfc-console-actors'),
        );

        // And the app's own choice is what actually resolves.
        $this->assertInstanceOf(
            EloquentUserProvider::class,
            auth(ConsoleGuardConfiguration::GUARD)->getProvider(),
        );
    }
}
