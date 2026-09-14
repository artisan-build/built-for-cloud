<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use PDO;

/** Default PostgreSQL provisioner backed by a real administrator PDO connection. */
final class PdoPostgresDatabaseProvisioner implements PostgresDatabaseProvisioner
{
    public function exists(PDO $administrator, string $databaseName): bool
    {
        PostgresRunIdentity::assertDatabaseName($databaseName);
        $statement = $administrator->prepare('SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = :database)');
        $statement->execute(['database' => $databaseName]);

        return filter_var($statement->fetchColumn(), FILTER_VALIDATE_BOOL);
    }

    public function create(PDO $administrator, string $databaseName): void
    {
        $administrator->exec('SET statement_timeout = 60000');
        $administrator->exec('CREATE DATABASE '.$this->quoteIdentifier($databaseName));
    }

    public function drop(PDO $administrator, string $databaseName): void
    {
        $administrator->exec('SET statement_timeout = 60000');
        $administrator->exec('DROP DATABASE '.$this->quoteIdentifier($databaseName).' WITH (FORCE)');
    }

    private function quoteIdentifier(string $identifier): string
    {
        PostgresRunIdentity::assertDatabaseName($identifier);

        return '"'.str_replace('"', '""', $identifier).'"';
    }
}
