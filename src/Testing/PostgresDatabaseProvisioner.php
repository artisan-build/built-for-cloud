<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use PDO;

/** Performs the PostgreSQL catalog operations needed by a disposable lane. */
interface PostgresDatabaseProvisioner
{
    public function exists(PDO $administrator, string $databaseName): bool;

    public function create(PDO $administrator, string $databaseName): void;

    public function drop(PDO $administrator, string $databaseName): void;
}
