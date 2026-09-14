<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Testing\DisposablePostgresLane;
use ArtisanBuild\BuiltForCloud\Testing\PostgresAdministrator;
use ArtisanBuild\BuiltForCloud\Testing\PostgresRunIdentity;
use ArtisanBuild\BuiltForCloud\Testing\PostgresTeardownResult;

function p6IdentityDirectory(): string
{
    $directory = sys_get_temp_dir().'/bfc-p6-identity-'.bin2hex(random_bytes(8));
    mkdir($directory, 0700);

    return $directory;
}

it('generates both required entropy dimensions without accepting a caller target', function (): void {
    $directory = p6IdentityDirectory();
    $identity = PostgresRunIdentity::generate($directory);
    $manifest = json_decode((string) file_get_contents($identity->manifestPath), true, flags: JSON_THROW_ON_ERROR);

    expect($identity->databaseName)->toMatch('/^bfc_p6_[a-f0-9]{32}$/')
        ->and($manifest['database_name'])->toBe($identity->databaseName)
        ->and($manifest['run_marker'])->toMatch('/^[a-f0-9]{64}$/')
        ->and($manifest['run_marker'])->not->toContain(substr($identity->databaseName, strlen('bfc_p6_')))
        ->and(fileperms($identity->manifestPath) & 0777)->toBe(0600)
        ->and(fn () => DisposablePostgresLane::create(
            administrator: new PostgresAdministrator('127.0.0.1', 5432, 'postgres', 'postgres', 'test-password'),
            privateManifestDirectory: $directory,
            databaseName: 'bfc_p6_'.str_repeat('a', 32),
        ))->toThrow(Error::class, 'Unknown named parameter');

    $identity->assertManifestEvidence();
    $identity->forgetManifest();
    rmdir($directory);
});

it('rejects every malformed run database identity', function (string $database): void {
    expect(fn () => PostgresRunIdentity::assertDatabaseName($database))
        ->toThrow(InvalidArgumentException::class, 'database name is invalid');
})->with([
    'caller-style shared name' => 'bfc_testing',
    'wrong prefix' => 'other_'.str_repeat('a', 32),
    'short entropy' => 'bfc_p6_'.str_repeat('a', 31),
    'long entropy' => 'bfc_p6_'.str_repeat('a', 33),
    'non-hex entropy' => 'bfc_p6_'.str_repeat('z', 32),
    'uppercase entropy' => 'bfc_p6_'.str_repeat('A', 32),
]);

it('fails closed when either private manifest identity copy is missing or changed', function (string $case): void {
    $directory = p6IdentityDirectory();
    $identity = PostgresRunIdentity::generate($directory);
    $manifest = json_decode((string) file_get_contents($identity->manifestPath), true, flags: JSON_THROW_ON_ERROR);

    if ($case === 'missing') {
        unlink($identity->manifestPath);
    } elseif ($case === 'database') {
        $manifest['database_name'] = 'bfc_p6_'.str_repeat('b', 32);
    } elseif ($case === 'marker') {
        $manifest['run_marker'] = str_repeat('c', 64);
    } elseif ($case === 'short-marker') {
        $manifest['run_marker'] = str_repeat('d', 63);
    } elseif ($case === 'schema') {
        $manifest['schema'] = 'test-created-wrong-schema';
    } else {
        $manifest['unknown'] = true;
    }

    if ($case !== 'missing') {
        file_put_contents($identity->manifestPath, json_encode($manifest, JSON_THROW_ON_ERROR));
    }

    expect(fn () => $identity->assertManifestEvidence())
        ->toThrow(RuntimeException::class, 'manual cleanup is required');

    @unlink($identity->manifestPath);
    rmdir($directory);
})->with(['missing', 'database', 'marker', 'short-marker', 'schema', 'unknown-field']);

it('requires an already-private manifest directory', function (): void {
    $directory = sys_get_temp_dir().'/bfc-p6-public-'.bin2hex(random_bytes(8));
    mkdir($directory, 0755);

    expect(fn () => PostgresRunIdentity::generate($directory))
        ->toThrow(InvalidArgumentException::class, 'must exist and be private');

    rmdir($directory);
});

it('keeps administrator coordinates separate from generated target configuration', function (): void {
    $administrator = new PostgresAdministrator('127.0.0.1', 5432, 'postgres', 'postgres', 'test-password');
    $target = 'bfc_p6_'.str_repeat('a', 32);
    $primary = $administrator->laravelConnection($target, 'bfc-p6-primary', 750);
    $secondary = $administrator->laravelConnection($target, 'bfc-p6-secondary', 750);

    expect($primary['database'])->toBe($target)
        ->and($secondary['database'])->toBe($target)
        ->and($primary['options'])->not->toBe($secondary['options'])
        ->and($primary['options'])->toContain('--lock_timeout=750ms')
        ->and($secondary['options'])->toContain('--lock_timeout=750ms')
        ->and($primary)->not->toHaveKey('admin_database');
});

it('reports teardown idempotence only as the result of an already verified drop', function (): void {
    $first = new PostgresTeardownResult(true, true, true, false, 'pass');
    $idempotent = new PostgresTeardownResult(true, true, true, true, 'pass');
    $partial = new PostgresTeardownResult(false, false, false, false, 'manual-cleanup-required');

    expect($first->jsonSerialize())->toBe([
        'database_absent' => true,
        'manifest_absent' => true,
        'marker_verified' => true,
        'already_dropped' => false,
        'verdict' => 'pass',
    ])->and($idempotent->alreadyDropped)->toBeTrue()
        ->and($partial->verdict)->toBe('manual-cleanup-required')
        ->and($partial->databaseAbsent)->toBeFalse();
});
