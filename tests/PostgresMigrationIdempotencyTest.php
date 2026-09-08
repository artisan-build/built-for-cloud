<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\Tests\Support\PostgresLane;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\Group;

#[Group('pgsql')]
final class PostgresMigrationIdempotencyTest extends TestCase
{
    use PostgresLane;

    public function test_migrate_fresh_can_run_twice_against_the_same_postgresql_database(): void
    {
        $this->assertSame('pgsql', DB::connection()->getDriverName());

        $this->artisan('migrate:fresh', ['--database' => 'pgsql_testing'])->assertSuccessful();
        $this->artisan('migrate:fresh', ['--database' => 'pgsql_testing'])->assertSuccessful();
    }

    public function test_full_package_postgresql_schema_resets_without_application_tables(): void
    {
        $this->artisan('migrate:fresh', ['--database' => 'pgsql_testing', '--force' => true])->assertSuccessful();
        $this->artisan('migrate:reset', ['--database' => 'pgsql_testing', '--force' => true])->assertSuccessful();

        $tables = collect(DB::connection('pgsql_testing')->select(
            "select tablename from pg_tables where schemaname = 'public' and tablename <> 'migrations'",
        ))->map(static fn (object $table): string => (string) $table->tablename)->all();

        $this->assertSame([], $tables);
    }
}
