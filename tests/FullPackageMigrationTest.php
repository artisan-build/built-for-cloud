<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use Illuminate\Support\Facades\DB;

final class FullPackageMigrationTest extends TestCase
{
    public function test_full_package_sqlite_schema_fresh_and_reset_leaves_no_application_tables(): void
    {
        $this->artisan('migrate:fresh', ['--force' => true])->assertSuccessful();

        $this->assertTrue(DB::getSchemaBuilder()->hasTable('users'));
        $this->assertTrue(DB::getSchemaBuilder()->hasTable('credentials'));
        $this->assertTrue(DB::getSchemaBuilder()->hasTable('invitations'));

        $this->artisan('migrate:reset', ['--force' => true])->assertSuccessful();

        $tables = collect(DB::select("select name from sqlite_master where type = 'table'"))
            ->map(static fn (object $table): string => (string) $table->name)
            ->reject(static fn (string $table): bool => in_array($table, ['migrations', 'sqlite_sequence'], true))
            ->values()
            ->all();

        $this->assertSame([], $tables);
    }
}
