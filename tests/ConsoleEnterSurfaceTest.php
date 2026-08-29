<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Orchestra\Testbench\Attributes\WithConfig;

/**
 * The door is MOUNTED OR ABSENT, never present-and-refusing (Console PRD
 * D12/D13, PR4 AC10).
 *
 * Three conditions have to hold before `POST /bfc/console/enter` exists,
 * and each is driven here because each fails differently:
 *
 *  1. the routes surface family is on (PRD 1.14) — an app that does not
 *     serve this package's HTTP contract serves none of it, the door
 *     included;
 *  2. the Console is enabled — off by default, and a deployment that
 *     never asked for delegated entry must not have a door. That one is
 *     driven in `tests/ConsoleDisabledTest.php`, which is the class
 *     that boots an app with the Console genuinely off;
 *  3. the reserved `bfc-console` guard resolves to THIS package's
 *     driver. An app that defined its own delegated guard keeps it (the
 *     package never overwrites one), and mounting an endpoint that
 *     hands signed bytes to `ConsoleGuard::redeem()` would be the
 *     package deciding how somebody else's guard works.
 *
 * `GET /bfc/meta`'s `console-enter` capability rides the same predicate
 * in every case, so the advertisement and the route can never disagree.
 *
 * PHPUnit-style on purpose: every one of them is consumed at provider
 * BOOT, so it must be in place before the application exists.
 */
final class ConsoleEnterSurfaceTest extends TestCase
{
    use RefreshDatabase;

    public function test_the_door_is_mounted_by_default_in_a_console_enabled_app(): void
    {
        // Refusing rather than missing: a 403 proves the route exists
        // where a 404 would not.
        $this->post('/bfc/console/enter', ['assertion' => 'nope'])->assertStatus(403);

        $this->assertContains('console-enter', (array) $this->getJson('/bfc/meta')->json('capabilities'));
    }

    public function test_the_chrome_interceptor_rides_the_same_predicate_as_the_door(): void
    {
        // Refusing rather than missing again: the structured 401 proves
        // the route exists where a 404 would not.
        $this->get('/bfc/console/chrome.js')->assertStatus(401)->assertHeader('BFC-Console-Reentry', '1');

        $this->assertContains('console-chrome-assets', (array) $this->getJson('/bfc/meta')->json('capabilities'));
    }

    #[WithConfig('built-for-cloud.surfaces.routes', false, false)]
    public function test_routes_off_unmounts_the_door_like_every_other_package_route(): void
    {
        $this->post('/bfc/console/enter', ['assertion' => 'nope'])->assertNotFound();
        $this->get('/bfc/console/chrome.js')->assertNotFound();
    }
}
