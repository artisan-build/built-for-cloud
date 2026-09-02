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
}
