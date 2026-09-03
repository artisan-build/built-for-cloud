<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Support;

use Illuminate\Database\Connection;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use RuntimeException;
use Throwable;

trait PostgresLane
{
    private const string POSTGRES_CONNECTION = 'pgsql_testing';

    private const string PROBE_CONNECTION = 'pgsql_testing_probe';

    private static bool $postgresLaneMigrated = false;

    protected function setUpPostgresLane(): void
    {
        $database = getenv('PGSQL_TESTING_DATABASE');

        if ($database === false || $database === '') {
            $this->markTestSkipped(
                'The Postgres lane is opt-in. Set PGSQL_TESTING_DATABASE and the other PGSQL_TESTING_* values.',
            );
        }

        config([
            'database.default' => self::POSTGRES_CONNECTION,
            'database.connections.'.self::PROBE_CONNECTION => config(
                'database.connections.'.self::POSTGRES_CONNECTION,
            ),
        ]);

        DB::purge(self::POSTGRES_CONNECTION);
        DB::purge(self::PROBE_CONNECTION);

        try {
            $this->postgresLaneConnection()->getPdo();
        } catch (Throwable $exception) {
            $this->markTestSkipped(
                'The configured Postgres lane is unreachable: '.$exception->getMessage(),
            );
        }

        if ($this->postgresLaneConnection()->getDriverName() !== 'pgsql') {
            throw new RuntimeException('The Postgres lane must use the pgsql driver.');
        }

        if (! self::$postgresLaneMigrated) {
            $status = Artisan::call('migrate:fresh', [
                '--database' => self::POSTGRES_CONNECTION,
                '--force' => true,
            ]);

            if ($status !== 0) {
                throw new RuntimeException('Postgres migrate:fresh failed: '.Artisan::output());
            }

            self::$postgresLaneMigrated = true;

            return;
        }

        $this->truncatePostgresLane();
    }

    protected function tearDownPostgresLane(): void
    {
        foreach ([self::PROBE_CONNECTION, self::POSTGRES_CONNECTION] as $name) {
            try {
                $connection = DB::connection($name);

                while ($connection->transactionLevel() > 0) {
                    $connection->rollBack();
                }
            } catch (Throwable) {
                // Purging below is the final rollback for an unusable connection.
            }

            DB::purge($name);
        }
    }

    protected function postgresLaneConnection(): Connection
    {
        return DB::connection(self::POSTGRES_CONNECTION);
    }

    protected function postgresLaneProbe(): Connection
    {
        return DB::connection(self::PROBE_CONNECTION);
    }

    private function truncatePostgresLane(): void
    {
        $tables = $this->postgresLaneConnection()->select(
            "select tablename from pg_tables where schemaname = 'public' and tablename <> 'migrations'",
        );

        if ($tables === []) {
            return;
        }

        $quoted = array_map(
            static fn (object $table): string => '"'.str_replace('"', '""', (string) $table->tablename).'"',
            $tables,
        );

        $this->postgresLaneConnection()->statement(
            'TRUNCATE TABLE '.implode(', ', $quoted).' RESTART IDENTITY CASCADE',
        );
    }
}
