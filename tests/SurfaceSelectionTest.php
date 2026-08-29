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
 * key: five independently selectable families (routes, migrations,
 * commands, listeners, data migrations), each defaulting ON, each
 * verifiably ABSENT when turned off. This is what lets capstan/reel stop
 * mounting `/bfc/*` from config instead of forking the provider. The
 * `data_migrations` family is exercised in InitialOwnershipClaimMintTest
 * alongside the D7 bug fix.
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

        $this->assertTrue(Schema::hasTable('credentials'));
        $this->assertArrayHasKey('bfc:credential:mint', Artisan::all());
        $this->assertTrue(Event::hasListeners(OwnershipReleasePending::class));
        $this->assertTrue(Event::hasListeners(OwnershipTransferred::class));
        $this->assertTrue((bool) config('built-for-cloud.surfaces.data_migrations'));
    }

    #[WithConfig('built-for-cloud.surfaces.routes', false, false)]
    public function test_routes_off_unmounts_every_package_route_but_keeps_the_middleware_aliases(): void
    {
        $packageRoutes = collect(Route::getRoutes()->getRoutes())
            ->filter(fn ($route): bool => str_starts_with($route->getActionName(), 'ArtisanBuild\\BuiltForCloud\\'));

        $this->assertCount(0, $packageRoutes);

        // The whole family is gone — the meta, ownership, onboarding,
        // claim and credential surfaces alike…
        $this->getJson('/bfc/meta')->assertNotFound();
        $this->postJson('/bfc/ownership/claim', ['token' => 'x'])->assertNotFound();
        $this->postJson('/bfc/claim', ['claim_code' => 'x', 'version' => 1])->assertNotFound();
        $this->getJson('/bfc/credentials')->assertNotFound();
        $this->getJson('/bfc/me/credentials')->assertNotFound();
        // …the console key-custody verb included: it is an ordinary
        // member of the routes family, not a surface of its own
        // (Console PRD D12).
        $this->postJson('/bfc/console/re-key', ['key_id' => 'k1', 'public_key' => str_repeat('a', 64)])
            ->assertNotFound();

        // …while the aliases stay registered, so an app with routes off
        // still gates its own routes (the MCP per-tool primitive included).
        $aliases = Route::getMiddleware();

        foreach (['bfc.auth', 'bfc.admin', 'bfc.token.admin', 'bfc.credential.admin', 'bfc.ability', 'bfc.hmac'] as $alias) {
            $this->assertArrayHasKey($alias, $aliases);
        }

        // The other families are untouched: independence, not a master switch.
        $this->assertTrue(Schema::hasTable('credentials'));
        $this->assertArrayHasKey('bfc:credential:mint', Artisan::all());
        $this->assertTrue(Event::hasListeners(OwnershipReleasePending::class));
    }

    #[WithConfig('built-for-cloud.surfaces.routes', false, false)]
    public function test_routes_off_unmounts_the_console_re_key_verb_while_its_command_survives(): void
    {
        // The re-key verb has two transports, and they belong to two
        // DIFFERENT surface families: an app that stops serving /bfc/*
        // keeps `bfc:console:re-key` and can still be re-keyed on the
        // box (Console PRD D12, PRD 1.14's independence).
        $this->postJson('/bfc/console/re-key', ['key_id' => 'k1', 'public_key' => str_repeat('a', 64)])
            ->assertNotFound();

        $this->assertArrayHasKey('bfc:console:re-key', Artisan::all());
    }

    #[WithConfig('built-for-cloud.surfaces.commands', false, false)]
    public function test_commands_off_unmounts_the_console_re_key_command(): void
    {
        $this->assertArrayNotHasKey('bfc:console:re-key', Artisan::all());
    }

    #[WithConfig('built-for-cloud.surfaces.migrations', false, false)]
    public function test_migrations_off_stops_loading_the_package_schema(): void
    {
        // Only the test-fixture users table exists; no package migration
        // was loaded into the migrator, so no package table was created.
        $this->assertTrue(Schema::hasTable('users'));

        foreach (['credentials', 'api_tokens', 'onboarding_tokens', 'ownership', 'ownership_claims', 'invitations', 'credential_audit_events'] as $table) {
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

        $this->assertArrayNotHasKey('token:create', $commands);
        $this->assertArrayNotHasKey('token:rotate', $commands);

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
