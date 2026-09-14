<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\Tests\Support\PostgresLane;
use Illuminate\Support\Facades\Artisan;
use PHPUnit\Framework\Attributes\Group;

#[Group('pgsql')]
final class PostgresPurposeMigrationTest extends Support\PurposeMigrationTestCase
{
    use PostgresLane;

    public function test_fresh_postgresql_schema_and_post_purpose_writers(): void
    {
        $this->assertFreshPurposeSchema('pgsql_testing');
    }

    public function test_real_postgresql_upgrade_retires_every_legacy_row_and_rollback_never_resurrects(): void
    {
        try {
            $this->assertUpgradeAndRollback('pgsql_testing');
        } finally {
            Artisan::call('migrate:fresh', [
                '--database' => 'pgsql_testing',
                '--force' => true,
            ]);
        }
    }
}
