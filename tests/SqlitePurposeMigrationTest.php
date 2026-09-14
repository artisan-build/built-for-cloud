<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use Illuminate\Support\Facades\Artisan;

final class SqlitePurposeMigrationTest extends Support\PurposeMigrationTestCase
{
    public function test_fresh_sqlite_schema_and_post_purpose_writers(): void
    {
        $this->assertSame(0, Artisan::call('migrate:fresh', ['--force' => true]), Artisan::output());
        $this->assertFreshPurposeSchema('testing');
    }

    public function test_real_sqlite_upgrade_retires_every_legacy_row_and_rollback_never_resurrects(): void
    {
        $this->assertUpgradeAndRollback('testing');
    }
}
