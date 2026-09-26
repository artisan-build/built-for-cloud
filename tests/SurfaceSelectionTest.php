<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\Events\OwnershipReleasePending;
use ArtisanBuild\BuiltForCloud\Events\OwnershipTransferred;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\Attributes\WithConfig;

/**
 * PRD 1.14 (fleet F2, WIDENED by Ed's ruling) — the surface-selection
 * key: independently selectable families (migrations, commands,
 * listeners, data migrations), each defaulting ON, each verifiably ABSENT
 * when turned off. Routes were a family too until every Built for Cloud
 * app got a UI: they now load in every app, and the retired key is
 * ignored. The `data_migrations` family is exercised in
 * InitialOwnershipClaimMintTest alongside the D7 bug fix.
 *
 * PHPUnit-style on purpose: surface keys are consumed at provider BOOT,
 * so they must be set before the app exists — per-method WithConfig
 * attributes are the tool for that.
 */
final class SurfaceSelectionTest extends TestCase
{
    use RefreshDatabase;

    public function test_every_surface_family_defaults_on(): void
    {
        $this->getJson('/bfc/meta')->assertOk();

        // Mounted by default, and refusing rather than missing: a 401
        // proves the route exists where a 404 would not.
        $this->getJson('/bfc/console/vitals')->assertUnauthorized();

        $this->assertTrue(Schema::hasTable('credentials'));
        $this->assertArrayHasKey('bfc:credential:mint', Artisan::all());
        $this->assertTrue(Event::hasListeners(OwnershipReleasePending::class));
        $this->assertTrue(Event::hasListeners(OwnershipTransferred::class));
        $this->assertTrue((bool) config('built-for-cloud.surfaces.data_migrations'));
    }

    #[WithConfig('built-for-cloud.surfaces.routes', false, false)]
    public function test_routes_mount_in_every_app_even_one_still_carrying_the_retired_routes_switch(): void
    {
        // Every Built for Cloud app has a UI and the full HTTP contract, so
        // routes are no longer a selectable family: an app whose config
        // still says `'routes' => false` gets them all the same.
        $this->getJson('/bfc/meta')->assertOk();
        $this->getJson('/bfc/console/vitals')->assertUnauthorized();
        $this->getJson('/bfc/credentials')->assertUnauthorized();
        $this->get('/bfc/login')->assertOk();
        $this->assertTrue(Route::has('bfc.ui.home'));

        $aliases = Route::getMiddleware();

        foreach (['bfc.auth', 'bfc.admin', 'bfc.credential.admin', 'bfc.ability', 'bfc.hmac', 'bfc.contract-major'] as $alias) {
            $this->assertArrayHasKey($alias, $aliases);
        }
    }

    #[WithConfig('built-for-cloud.surfaces.commands', false, false)]
    public function test_commands_off_unmounts_the_console_re_key_command(): void
    {
        $this->assertArrayNotHasKey('bfc:console:re-key', Artisan::all());
    }

    #[WithConfig('built-for-cloud.surfaces.migrations', false, false)]
    public function test_migrations_off_stops_loading_the_package_schema(): void
    {
        foreach (['users', 'bfc_authority', 'credentials', 'onboarding_tokens', 'ownership', 'ownership_claims', 'invitations', 'credential_audit_events'] as $table) {
            $this->assertFalse(Schema::hasTable($table), "Expected the {$table} table to be absent with the migrations surface off.");
        }

        // Independence: routes and commands still mount. (An app taking
        // this shape owns the schema itself — the routes still expect the
        // tables to exist, wherever its own migrations put them.)
        $packageRoutes = collect(Route::getRoutes()->getRoutes())
            ->filter(fn ($route): bool => str_starts_with($route->getActionName(), 'ArtisanBuild\\BuiltForCloud\\'));

        $this->assertGreaterThan(0, $packageRoutes->count());
        $this->assertArrayHasKey('bfc:credential:mint', Artisan::all());
    }

    #[WithConfig('built-for-cloud.surfaces.commands', false, false)]
    public function test_commands_off_registers_no_package_command(): void
    {
        $commands = Artisan::all();

        foreach (array_keys($commands) as $name) {
            $this->assertFalse(
                str_starts_with((string) $name, 'bfc:'),
                "Expected no bfc:* command with the commands surface off; found {$name}.",
            );
        }

        // Independence: everything else still mounts.
        $this->getJson('/bfc/meta')->assertOk();
        $this->assertTrue(Schema::hasTable('credentials'));
        $this->assertTrue(Event::hasListeners(OwnershipReleasePending::class));
    }

    #[WithConfig('built-for-cloud.surfaces.listeners', false, false)]
    public function test_listeners_off_registers_no_package_listener(): void
    {
        $this->assertFalse(Event::hasListeners(OwnershipReleasePending::class));
        $this->assertFalse(Event::hasListeners(OwnershipTransferred::class));

        // Independence: everything else still mounts.
        $this->getJson('/bfc/meta')->assertOk();
        $this->assertTrue(Schema::hasTable('credentials'));
        $this->assertArrayHasKey('bfc:credential:mint', Artisan::all());
    }
}
