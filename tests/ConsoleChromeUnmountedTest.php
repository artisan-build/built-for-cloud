<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\Console\ConsoleChrome;
use ArtisanBuild\BuiltForCloud\Console\ConsoleGuardConfiguration;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Route;

/**
 * The chrome on a deployment that mounts no package routes (PRD 1.14's
 * routes family switched off): full attribution, and no `<script src>`
 * pointing at a URL nobody serves.
 *
 * PHPUnit-style because the surface flag is read at provider boot, so it
 * has to be in place before the application exists; a per-test
 * `config()` call is far too late and would leave the routes mounted
 * while the test believed otherwise.
 */
final class ConsoleChromeUnmountedTest extends TestCase
{
    use RefreshDatabase;

    /**
     * @param  Application  $app
     */
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('built-for-cloud.surfaces.routes', false);
    }

    public function test_renders_no_reentry_script_when_the_interceptor_route_is_not_mounted(): void
    {
        Route::middleware([StartSession::class, 'bfc.console', 'auth:'.ConsoleGuardConfiguration::GUARD])
            ->get('/chrome-console', fn () => view('bfc::layout'));

        // Honest degradation rather than a link to a 404: the same
        // stance the structured 401 takes when no `reentry_url` is
        // configured. The chrome still says who the operator is,
        // because that part is true.
        $this->assertFalse(Route::has(ConsoleChrome::SCRIPT_ROUTE));

        $actor = consoleActor(displayName: 'Jane Operator');

        $html = (string) $this->withSession(consoleSessionState($actor))
            ->get('/chrome-console')->assertOk()->getContent();

        $this->assertStringContainsString('Jane Operator', $html);
        $this->assertStringContainsString(ConsoleChrome::ELEMENT_ID, $html);
        $this->assertStringNotContainsString('/bfc/console/chrome.js', $html);
        $this->assertStringNotContainsString('<script', $html);
    }
}
