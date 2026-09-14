<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\DatabaseManager;
use PDO;
use RuntimeException;
use Throwable;

/** Owns one random PostgreSQL database from creation through verified teardown. */
final class DisposablePostgresLane
{
    public const string PRIMARY_CONNECTION = 'pgsql_testing';

    public const string SECONDARY_CONNECTION = 'pgsql_testing_probe';

    public const int LOCK_TIMEOUT_MILLISECONDS = 750;

    private ?DatabaseManager $manager = null;

    private bool $dropped = false;

    private function __construct(
        private readonly PostgresAdministrator $administrator,
        private readonly PostgresRunIdentity $identity,
    ) {}

    public static function create(PostgresAdministrator $administrator, string $privateManifestDirectory): self
    {
        $identity = PostgresRunIdentity::generate($privateManifestDirectory);

        try {
            $admin = $administrator->connect();
        } catch (Throwable $exception) {
            $identity->forgetManifest();

            throw $exception;
        }

        try {
            self::assertAdministratorIsSeparate($admin, $identity->databaseName);

            if (self::databaseExists($admin, $identity->databaseName)) {
                $identity->forgetManifest();

                throw new RuntimeException('The generated PostgreSQL target already exists; creation was refused.');
            }

            $admin->exec('SET statement_timeout = 60000');
            $admin->exec('CREATE DATABASE '.self::quoteIdentifier($identity->databaseName));
        } catch (Throwable $exception) {
            if (! self::databaseExistsSafely($admin, $identity->databaseName)) {
                try {
                    $identity->forgetManifest();
                } catch (Throwable) {
                    // Preserve the creation failure; no database exists to clean up.
                }
            }

            throw $exception;
        }

        $lane = new self($administrator, $identity);

        try {
            $target = $administrator->connect($identity->databaseName);
            $identity->installDatabaseEvidence($target);
            $identity->assertManifestEvidence();
            $identity->assertDatabaseEvidence($target);
        } catch (Throwable $exception) {
            throw new RuntimeException(
                'The PostgreSQL target was created but could not be marked; manual cleanup is required.',
                previous: $exception,
            );
        }

        return $lane;
    }

    public function databaseName(): string
    {
        return $this->identity->databaseName;
    }

    public function manifestPath(): string
    {
        return $this->identity->manifestPath;
    }

    public function configure(Repository $config, DatabaseManager $manager): void
    {
        $this->assertOwned();
        $config->set('database.default', self::PRIMARY_CONNECTION);
        $config->set(
            'database.connections.'.self::PRIMARY_CONNECTION,
            $this->administrator->laravelConnection(
                $this->databaseName(),
                'bfc-p6-primary',
                self::LOCK_TIMEOUT_MILLISECONDS,
            ),
        );
        $config->set(
            'database.connections.'.self::SECONDARY_CONNECTION,
            $this->administrator->laravelConnection(
                $this->databaseName(),
                'bfc-p6-secondary',
                self::LOCK_TIMEOUT_MILLISECONDS,
            ),
        );
        $manager->purge(self::PRIMARY_CONNECTION);
        $manager->purge(self::SECONDARY_CONNECTION);
        $primary = $manager->connection(self::PRIMARY_CONNECTION);
        $secondary = $manager->connection(self::SECONDARY_CONNECTION);
        $primaryPdo = $primary->getPdo();
        $secondaryPdo = $secondary->getPdo();

        if ($primary->getDriverName() !== 'pgsql'
            || $secondary->getDriverName() !== 'pgsql'
            || $primaryPdo === $secondaryPdo
            || $primary->scalar('select current_database()') !== $this->databaseName()
            || $secondary->scalar('select current_database()') !== $this->databaseName()
            || $primary->scalar('show lock_timeout') !== self::LOCK_TIMEOUT_MILLISECONDS.'ms'
            || $secondary->scalar('show lock_timeout') !== self::LOCK_TIMEOUT_MILLISECONDS.'ms'
            || $primary->scalar('select pg_backend_pid()') === $secondary->scalar('select pg_backend_pid()')) {
            throw new RuntimeException('The PostgreSQL lane did not establish two distinct bounded target connections.');
        }

        $this->manager = $manager;
    }

    public function migrate(callable $migration): void
    {
        $this->assertOwned();
        $status = $migration(self::PRIMARY_CONNECTION);

        if ($status !== 0) {
            throw new RuntimeException('The PostgreSQL lane migration failed.');
        }

        $this->assertOwned();
    }

    public function assertOwned(): void
    {
        if ($this->dropped) {
            throw new RuntimeException('The PostgreSQL lane has already been dropped.');
        }

        $this->identity->assertManifestEvidence();
        $admin = $this->administrator->connect();
        self::assertAdministratorIsSeparate($admin, $this->databaseName());

        if (! self::databaseExists($admin, $this->databaseName())) {
            throw new RuntimeException('The owned PostgreSQL database is missing; manual cleanup is required.');
        }

        $this->identity->assertDatabaseEvidence($this->administrator->connect($this->databaseName()));
    }

    public function teardown(): PostgresTeardownResult
    {
        if ($this->dropped) {
            return new PostgresTeardownResult(true, true, true, true, 'pass');
        }

        $this->assertOwned();
        $this->manager?->purge(self::SECONDARY_CONNECTION);
        $this->manager?->purge(self::PRIMARY_CONNECTION);
        $admin = $this->administrator->connect();
        self::assertAdministratorIsSeparate($admin, $this->databaseName());
        $admin->exec('SET statement_timeout = 60000');
        $admin->exec('DROP DATABASE '.self::quoteIdentifier($this->databaseName()).' WITH (FORCE)');

        if (self::databaseExists($admin, $this->databaseName())) {
            throw new RuntimeException('The verified PostgreSQL database remained after teardown; manual cleanup is required.');
        }

        $this->identity->forgetManifest();
        $this->dropped = true;

        return new PostgresTeardownResult(true, true, true, false, 'pass');
    }

    private static function assertAdministratorIsSeparate(PDO $administrator, string $target): void
    {
        if ($administrator->query('SELECT current_database()')->fetchColumn() === $target) {
            throw new RuntimeException('The administrator connection must be separate from the generated target.');
        }
    }

    private static function databaseExists(PDO $administrator, string $database): bool
    {
        $statement = $administrator->prepare('SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = :database)');
        $statement->execute(['database' => $database]);

        return filter_var($statement->fetchColumn(), FILTER_VALIDATE_BOOL);
    }

    private static function databaseExistsSafely(PDO $administrator, string $database): bool
    {
        try {
            return self::databaseExists($administrator, $database);
        } catch (Throwable) {
            return true;
        }
    }

    private static function quoteIdentifier(string $identifier): string
    {
        PostgresRunIdentity::assertDatabaseName($identifier);

        return '"'.str_replace('"', '""', $identifier).'"';
    }
}
