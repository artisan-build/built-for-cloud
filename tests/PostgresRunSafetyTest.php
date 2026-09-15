<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Testing\DisposablePostgresLane;
use ArtisanBuild\BuiltForCloud\Testing\PostgresAdministrator;
use ArtisanBuild\BuiltForCloud\Testing\PostgresDatabaseProvisioner;
use ArtisanBuild\BuiltForCloud\Testing\PostgresRunIdentity;
use ArtisanBuild\BuiltForCloud\Tests\Support\PostgresLaneState;
use PDO;
use Symfony\Component\Process\Process;

function p6SafetyAdministrator(): PostgresAdministrator
{
    if (! PostgresLaneState::isConfigured()) {
        if (PostgresLaneState::isExplicitlyRequested()) {
            throw new RuntimeException('The requested PostgreSQL safety controls require the PGSQL_TESTING_* administrator connection.');
        }

        test()->markTestSkipped('The PostgreSQL safety controls are opt-in.');
    }

    return PostgresAdministrator::fromEnvironment();
}

function p6SafetyDirectory(): string
{
    $directory = sys_get_temp_dir().'/bfc-p6-safety-'.bin2hex(random_bytes(8));
    mkdir($directory, 0700);

    return $directory;
}

function p6SafetyIdentifier(string $database): string
{
    PostgresRunIdentity::assertDatabaseName($database);

    return '"'.str_replace('"', '""', $database).'"';
}

function p6SafetyDrop(PDO $administrator, string $database): void
{
    $administrator->exec('DROP DATABASE IF EXISTS '.p6SafetyIdentifier($database).' WITH (FORCE)');
}

it('refuses a pre-existing generated target and removes only its unused manifest', function (): void {
    $administrator = p6SafetyAdministrator();
    $directory = p6SafetyDirectory();
    $unrelatedDirectory = p6SafetyDirectory();
    $unrelated = DisposablePostgresLane::create($administrator, $unrelatedDirectory);
    $admin = $administrator->connect();
    $collision = new class implements PostgresDatabaseProvisioner
    {
        public ?string $databaseName = null;

        public function exists(PDO $administrator, string $databaseName): bool
        {
            if ($this->databaseName === null) {
                $this->databaseName = $databaseName;
                $administrator->exec('CREATE DATABASE '.p6SafetyIdentifier($databaseName));
            }

            return true;
        }

        public function create(PDO $administrator, string $databaseName): void
        {
            throw new LogicException('Creation must not run after a collision.');
        }

        public function drop(PDO $administrator, string $databaseName): void
        {
            throw new LogicException('The refused collision is cleaned up explicitly.');
        }
    };

    try {
        expect(fn () => DisposablePostgresLane::create($administrator, $directory, $collision))
            ->toThrow(RuntimeException::class, 'already exists')
            ->and($collision->databaseName)->toMatch('/^bfc_p6_[a-f0-9]{32}$/')
            ->and(glob($directory.'/*.json'))->toBe([]);
        $unrelated->assertOwned();
    } finally {
        if ($collision->databaseName !== null) {
            p6SafetyDrop($admin, $collision->databaseName);
        }
        $unrelated->teardown();
        rmdir($directory);
        rmdir($unrelatedDirectory);
    }
})->group('pgsql');

it('fails closed on either marker copy while an unrelated owned database survives', function (): void {
    $administrator = p6SafetyAdministrator();
    $directoryA = p6SafetyDirectory();
    $directoryB = p6SafetyDirectory();
    $laneA = DisposablePostgresLane::create($administrator, $directoryA);
    $laneB = DisposablePostgresLane::create($administrator, $directoryB);
    $targetA = $administrator->connect($laneA->databaseName());
    $manifest = (string) file_get_contents($laneA->manifestPath());
    $marker = json_decode($manifest, true, flags: JSON_THROW_ON_ERROR)['run_marker'];

    try {
        $targetA->exec('COMMENT ON DATABASE '.p6SafetyIdentifier($laneA->databaseName())." IS 'mismatched'");
        expect(fn () => $laneA->teardown())->toThrow(RuntimeException::class, 'manual cleanup is required');
        $laneB->assertOwned();

        $quotedMarker = $targetA->quote($marker);
        expect($quotedMarker)->toBeString();
        $targetA->exec('COMMENT ON DATABASE '.p6SafetyIdentifier($laneA->databaseName()).' IS '.$quotedMarker);
        unlink($laneA->manifestPath());
        expect(fn () => $laneA->teardown())->toThrow(RuntimeException::class, 'manual cleanup is required');
        file_put_contents($laneA->manifestPath(), $manifest);
        chmod($laneA->manifestPath(), 0600);

        expect($laneA->teardown()->verdict)->toBe('pass')
            ->and($laneA->teardown()->alreadyDropped)->toBeTrue();
        $laneB->assertOwned();
    } finally {
        try {
            if (is_file($laneA->manifestPath())) {
                file_put_contents($laneA->manifestPath(), $manifest);
                chmod($laneA->manifestPath(), 0600);
                $quotedMarker = $targetA->quote($marker);
                if (is_string($quotedMarker)) {
                    $targetA->exec('COMMENT ON DATABASE '.p6SafetyIdentifier($laneA->databaseName()).' IS '.$quotedMarker);
                }
                $laneA->teardown();
            }
        } finally {
            $laneB->teardown();
            @rmdir($directoryA);
            @rmdir($directoryB);
        }
    }
})->group('pgsql');

it('exports the generated target database to child processes', function (): void {
    $lane = PostgresLaneState::lane(p6SafetyAdministrator());
    $process = new Process([
        PHP_BINARY,
        '-r',
        'fwrite(STDOUT, (string) getenv("PGSQL_TESTING_DATABASE"));',
    ]);
    $process->mustRun();

    expect($process->getOutput())->toBe($lane->databaseName());
})->group('pgsql');
