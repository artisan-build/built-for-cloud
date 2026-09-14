<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Support;

use ArtisanBuild\BuiltForCloud\Testing\DisposablePostgresLane;
use ArtisanBuild\BuiltForCloud\Testing\P6GateContract;
use ArtisanBuild\BuiltForCloud\Testing\PostgresAdministrator;
use RuntimeException;

/** One run-owned database shared by all PostgreSQL test classes in this Pest process. */
final class PostgresLaneState
{
    private static ?DisposablePostgresLane $lane = null;

    private static bool $migrated = false;

    /** @var array<string, string> */
    private static array $cases = [];

    private static ?string $manifestDirectory = null;

    private static string|false|null $previousDatabaseEnvironment = null;

    public static function isConfigured(): bool
    {
        foreach (['PGSQL_TESTING_HOST', 'PGSQL_TESTING_ADMIN_DATABASE', 'PGSQL_TESTING_USERNAME'] as $name) {
            $value = getenv($name);

            if (! is_string($value) || $value === '') {
                return false;
            }
        }

        return true;
    }

    public static function isExplicitlyRequested(): bool
    {
        if (getenv('BFC_P6_PGSQL_REQUESTED') === '1') {
            return true;
        }

        $arguments = $_SERVER['argv'] ?? [];
        $joined = is_array($arguments) ? implode(' ', array_filter($arguments, 'is_string')) : '';

        return preg_match('/(?:^|\s)--group(?:=|\s+)pgsql(?:\s|$)/', $joined) === 1;
    }

    public static function lane(PostgresAdministrator $administrator): DisposablePostgresLane
    {
        if (self::$lane instanceof DisposablePostgresLane) {
            return self::$lane;
        }

        $directory = sys_get_temp_dir().'/bfc-p6-pgsql-'.getmypid().'-'.bin2hex(random_bytes(8));
        if (! mkdir($directory, 0700)) {
            throw new RuntimeException('The private PostgreSQL lane directory could not be created.');
        }

        self::$manifestDirectory = $directory;
        self::$lane = DisposablePostgresLane::create($administrator, $directory);
        self::$previousDatabaseEnvironment = getenv('PGSQL_TESTING_DATABASE');
        self::exportDatabaseEnvironment(self::$lane->databaseName());
        register_shutdown_function(self::finish(...));

        return self::$lane;
    }

    public static function migrated(): bool
    {
        return self::$migrated;
    }

    public static function markMigrated(): void
    {
        self::$migrated = true;
    }

    public static function recordCase(string $case): void
    {
        if (! in_array($case, P6GateContract::POSTGRES_CASES, true)) {
            throw new RuntimeException("Unknown P6 PostgreSQL case [{$case}].");
        }

        self::$cases[$case] = 'pass';
    }

    public static function finish(): void
    {
        if (! self::$lane instanceof DisposablePostgresLane) {
            return;
        }

        $lane = self::$lane;
        $teardown = $lane->teardown();
        $stampPath = getenv('BFC_P6_PGSQL_STAMP');

        if (is_string($stampPath) && $stampPath !== '') {
            $cases = [];
            foreach (P6GateContract::POSTGRES_CASES as $case) {
                $cases[$case] = self::$cases[$case] ?? 'not-run';
            }

            $stamp = [
                'schema' => 'bfc.p6.postgres.v1',
                'database_name' => $lane->databaseName(),
                'run_marker_verified' => $teardown->markerVerified,
                'cases' => $cases,
                'teardown' => $teardown,
            ];
            file_put_contents(
                $stampPath,
                json_encode($stamp, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)."\n",
            );
        }

        self::restoreDatabaseEnvironment();

        if (is_string(self::$manifestDirectory)) {
            @rmdir(self::$manifestDirectory);
        }

        self::$lane = null;
    }

    private static function exportDatabaseEnvironment(string $database): void
    {
        putenv('PGSQL_TESTING_DATABASE='.$database);
        $_SERVER['PGSQL_TESTING_DATABASE'] = $database;
        $_ENV['PGSQL_TESTING_DATABASE'] = $database;
    }

    private static function restoreDatabaseEnvironment(): void
    {
        if (self::$previousDatabaseEnvironment === false) {
            putenv('PGSQL_TESTING_DATABASE');
            unset($_SERVER['PGSQL_TESTING_DATABASE'], $_ENV['PGSQL_TESTING_DATABASE']);
        } elseif (is_string(self::$previousDatabaseEnvironment)) {
            self::exportDatabaseEnvironment(self::$previousDatabaseEnvironment);
        }

        self::$previousDatabaseEnvironment = null;
    }
}
