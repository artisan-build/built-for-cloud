<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Throwable;

final class PostgresMigrationIdempotencyTest extends TestCase
{
    /**
     * @param  Application  $app
     */
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $database = getenv('BFC_POSTGRES_DATABASE');

        if ($database === false || $database === '') {
            return;
        }

        $app['config']->set('database.default', 'bfc-postgres');
        $app['config']->set('database.connections.bfc-postgres', [
            'driver' => 'pgsql',
            'host' => $this->environment('BFC_POSTGRES_HOST', '127.0.0.1'),
            'port' => $this->environment('BFC_POSTGRES_PORT', '5432'),
            'database' => $database,
            'username' => $this->environment('BFC_POSTGRES_USERNAME', 'postgres'),
            'password' => $this->environment('BFC_POSTGRES_PASSWORD', ''),
            'charset' => 'utf8',
            'prefix' => '',
            'prefix_indexes' => true,
            'search_path' => 'public',
            'sslmode' => 'prefer',
        ]);
    }

    public function test_migrate_fresh_can_run_twice_against_the_same_postgresql_database(): void
    {
        if (getenv('BFC_POSTGRES_DATABASE') === false || getenv('BFC_POSTGRES_DATABASE') === '') {
            $this->markTestSkipped(
                'PostgreSQL migration regression proof skipped: BFC_POSTGRES_DATABASE is not configured.',
            );
        }

        try {
            DB::connection()->getPdo();
        } catch (Throwable) {
            $this->markTestSkipped(
                'PostgreSQL migration regression proof skipped: the configured PostgreSQL server is unavailable.',
            );
        }

        $this->assertSame('pgsql', DB::connection()->getDriverName());

        $this->artisan('migrate:fresh')->assertSuccessful();
        $this->artisan('migrate:fresh')->assertSuccessful();
    }

    private function environment(string $name, string $default): string
    {
        $value = getenv($name);

        return $value === false ? $default : $value;
    }
}
