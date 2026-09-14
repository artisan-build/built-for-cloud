<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use InvalidArgumentException;
use JsonException;
use PDO;
use RuntimeException;

/** Run-owned database identity whose marker is intentionally never exposed by its API. */
final class PostgresRunIdentity
{
    public const string DATABASE_PREFIX = 'bfc_p6_';

    public const string MANIFEST_SCHEMA = 'bfc.p6.postgres-run.v1';

    public const string MARKER_TABLE = 'bfc_p6_run_identity';

    private function __construct(
        public readonly string $databaseName,
        public readonly string $manifestPath,
        #[\SensitiveParameter]
        private readonly string $marker,
    ) {}

    public static function generate(string $manifestDirectory): self
    {
        self::assertPrivateDirectory($manifestDirectory);

        $databaseName = self::DATABASE_PREFIX.bin2hex(random_bytes(16));
        $marker = bin2hex(random_bytes(32));
        $path = $manifestDirectory.'/'.$databaseName.'.json';
        $manifest = json_encode([
            'schema' => self::MANIFEST_SCHEMA,
            'database_name' => $databaseName,
            'run_marker' => $marker,
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $file = fopen($path, 'xb');

        if ($file === false) {
            throw new RuntimeException('The private PostgreSQL run manifest could not be created.');
        }

        try {
            if (! chmod($path, 0600) || fwrite($file, $manifest) !== strlen($manifest) || ! fflush($file)) {
                throw new RuntimeException('The private PostgreSQL run manifest could not be persisted.');
            }
        } catch (\Throwable $exception) {
            fclose($file);
            @unlink($path);

            throw $exception;
        }

        fclose($file);

        return new self($databaseName, $path, $marker);
    }

    public static function assertDatabaseName(string $databaseName): void
    {
        if (preg_match('/^bfc_p6_[a-f0-9]{32}$/D', $databaseName) !== 1) {
            throw new InvalidArgumentException('The PostgreSQL run database name is invalid.');
        }
    }

    public function installDatabaseEvidence(PDO $target): void
    {
        $target->exec('CREATE TABLE '.self::MARKER_TABLE.' (database_name varchar(39) PRIMARY KEY, run_marker char(64) NOT NULL)');
        $statement = $target->prepare('INSERT INTO '.self::MARKER_TABLE.' (database_name, run_marker) VALUES (:database_name, :run_marker)');
        $statement->execute([
            'database_name' => $this->databaseName,
            'run_marker' => $this->marker,
        ]);
    }

    public function assertManifestEvidence(): void
    {
        $manifest = $this->readManifest();

        if (($manifest['database_name'] ?? null) !== $this->databaseName
            || ! is_string($manifest['run_marker'] ?? null)
            || ! hash_equals($this->marker, $manifest['run_marker'])) {
            throw new RuntimeException('PostgreSQL run manifest identity verification failed; manual cleanup is required.');
        }
    }

    public function assertDatabaseEvidence(PDO $target): void
    {
        $database = $target->query('SELECT current_database()')->fetchColumn();
        $row = $target->query('SELECT database_name, run_marker FROM '.self::MARKER_TABLE)->fetch();

        if ($database !== $this->databaseName
            || ! is_array($row)
            || ($row['database_name'] ?? null) !== $this->databaseName
            || ! is_string($row['run_marker'] ?? null)
            || ! hash_equals($this->marker, $row['run_marker'])) {
            throw new RuntimeException('PostgreSQL database identity verification failed; manual cleanup is required.');
        }
    }

    public function forgetManifest(): void
    {
        if (is_file($this->manifestPath) && ! unlink($this->manifestPath)) {
            throw new RuntimeException('The verified PostgreSQL run manifest could not be removed.');
        }
    }

    /** @return array{schema: string, database_name: string, run_marker: string} */
    private function readManifest(): array
    {
        $contents = @file_get_contents($this->manifestPath);

        try {
            $manifest = is_string($contents) ? json_decode($contents, true, flags: JSON_THROW_ON_ERROR) : null;
        } catch (JsonException $exception) {
            throw new RuntimeException('PostgreSQL run manifest identity verification failed; manual cleanup is required.', previous: $exception);
        }

        if (! is_array($manifest)
            || array_keys($manifest) !== ['schema', 'database_name', 'run_marker']
            || ($manifest['schema'] ?? null) !== self::MANIFEST_SCHEMA
            || ! is_string($manifest['database_name'] ?? null)
            || ! is_string($manifest['run_marker'] ?? null)) {
            throw new RuntimeException('PostgreSQL run manifest identity verification failed; manual cleanup is required.');
        }

        self::assertDatabaseName($manifest['database_name']);

        if (preg_match('/^[a-f0-9]{64}$/D', $manifest['run_marker']) !== 1) {
            throw new RuntimeException('PostgreSQL run manifest identity verification failed; manual cleanup is required.');
        }

        return $manifest;
    }

    private static function assertPrivateDirectory(string $directory): void
    {
        $resolved = realpath($directory);
        $mode = is_string($resolved) ? fileperms($resolved) : false;

        if (! is_string($resolved) || ! is_dir($resolved) || $mode === false || ($mode & 0077) !== 0) {
            throw new InvalidArgumentException('The PostgreSQL run manifest directory must exist and be private.');
        }
    }
}
