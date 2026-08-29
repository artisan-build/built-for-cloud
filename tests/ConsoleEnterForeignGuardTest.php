<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\Console\ConsoleGuardConfiguration;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Testing\RefreshDatabase;

/**
 * The third condition, which needs the app's OWN guard defined before
 * the package boots — so it gets its own case class rather than an
 * attribute.
 */
final class ConsoleEnterForeignGuardTest extends TestCase
{
    use RefreshDatabase;

    /**
     * @param  Application  $app
     */
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        // An app that took the first rule: it defined its own
        // `bfc-console` guard, and the package steps aside entirely.
        $app['config']->set('auth.guards.'.ConsoleGuardConfiguration::GUARD, [
            'driver' => 'session',
            'provider' => 'users',
        ]);
    }

    public function test_an_app_that_owns_the_guard_owns_entry_too(): void
    {
        $this->assertSame(
            'session',
            config('auth.guards.'.ConsoleGuardConfiguration::GUARD.'.driver'),
        );

        $this->post('/bfc/console/enter', ['assertion' => 'nope'])->assertNotFound();

        // …and the capability is not advertised, so a control plane is
        // never told it can hand an operator to a door that is not there.
        $capabilities = (array) $this->getJson('/bfc/meta')->json('capabilities');

        $this->assertNotContains('console-enter', $capabilities);

        // `console-guard` still IS advertised: the delegated-session
        // machinery is enabled, and that capability describes the
        // machinery rather than the door.
        $this->assertContains('console-guard', $capabilities);
    }
}
