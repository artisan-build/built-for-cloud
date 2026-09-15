<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Support;

use ArtisanBuild\BuiltForCloud\Testing\DisposablePostgresLane;
use ArtisanBuild\BuiltForCloud\Testing\PostgresAdministrator;
use Illuminate\Database\Connection;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use RuntimeException;
use Throwable;

trait PostgresLane
{
    protected function setUpPostgresLane(): void
    {
        if (! PostgresLaneState::isConfigured()) {
            if (PostgresLaneState::isExplicitlyRequested()) {
                throw new RuntimeException(
                    'The requested PostgreSQL lane requires PGSQL_TESTING_HOST, '
                    .'PGSQL_TESTING_ADMIN_DATABASE, and PGSQL_TESTING_USERNAME.',
                );
            }

            $this->markTestSkipped(
                'The PostgreSQL lane is opt-in. Supply the PGSQL_TESTING_* administrator connection.',
            );
        }

        $lane = PostgresLaneState::lane(PostgresAdministrator::fromEnvironment());
        $lane->configure(app('config'), app('db'));

        if (! PostgresLaneState::migrated()) {
            $lane->migrate(static fn (string $connection): int => Artisan::call('migrate:fresh', [
                '--database' => $connection,
                '--force' => true,
            ]));
            PostgresLaneState::markMigrated();

            return;
        }

        $this->truncatePostgresLane();
    }

    protected function tearDownPostgresLane(): void
    {
        foreach ([DisposablePostgresLane::SECONDARY_CONNECTION, DisposablePostgresLane::PRIMARY_CONNECTION] as $name) {
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
        return DB::connection(DisposablePostgresLane::PRIMARY_CONNECTION);
    }

    protected function postgresLaneProbe(): Connection
    {
        return DB::connection(DisposablePostgresLane::SECONDARY_CONNECTION);
    }

    protected function recordPostgresCase(string $case): void
    {
        PostgresLaneState::recordCase($case);
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
