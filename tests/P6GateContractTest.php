<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\BuiltForCloud;
use ArtisanBuild\BuiltForCloud\HttpContract;
use ArtisanBuild\BuiltForCloud\Testing\P6GateContract;
use ArtisanBuild\BuiltForCloud\Testing\P6GateStamp;
use ArtisanBuild\BuiltForCloud\Testing\SharedRuntimeIdentity;

/** @return array<string, mixed> */
function p6ValidStamp(): array
{
    $sha = str_repeat('a', 40);
    $database = 'bfc_p6_'.str_repeat('b', 32);
    $roles = [];
    foreach (P6GateContract::SHARED_ROLES as $role) {
        $roles[$role] = [
            'driver' => 'database',
            'version' => 'postgresql-17.4',
            'identity' => $database.':'.$role,
        ];
    }
    $shared = (new SharedRuntimeIdentity($database, $roles))->jsonSerialize();
    $commands = [];
    foreach (P6GateContract::COORDINATOR_COMMANDS as $command) {
        $commands[$command] = ['exit_code' => 0, 'verdict' => 'pass'];
    }

    return [
        'schema' => P6GateContract::SCHEMA,
        'candidate_sha' => $sha,
        'archive' => [
            'source' => 'composer-package-dist-archive',
            'candidate_sha' => $sha,
            'sha256' => str_repeat('c', 64),
            'installed_version' => '0.0.0+p6c.'.$sha,
        ],
        'runtime' => ['php' => '8.4.13', 'laravel' => '13.24.0', 'postgres' => '17.4'],
        'postgres' => [
            'database_name' => $database,
            'matrix_database_name' => 'bfc_p6_'.str_repeat('d', 32),
            'relationship' => 'separate-run-owned-databases',
            'run_marker_verified' => true,
            'cases' => array_fill_keys(P6GateContract::POSTGRES_CASES, 'pass'),
        ],
        'shared_runtime' => ['node_a' => $shared, 'node_b' => $shared],
        'listeners' => [
            'node_a' => ['pid' => 101, 'port' => 41001, 'address' => '127.0.0.1:41001', 'identity_verified' => true],
            'node_b' => ['pid' => 102, 'port' => 41002, 'address' => '127.0.0.1:41002', 'identity_verified' => true],
        ],
        'commands' => $commands,
        'cases' => array_fill_keys(P6GateContract::LIVE_CASES, 'pass'),
        'teardown' => [
            'bounded' => true,
            'listeners_absent' => true,
            'database_absent' => true,
            'manifest_absent' => true,
            'verdict' => 'pass',
        ],
        'overall_verdict' => 'pass',
        'exit_code' => 0,
    ];
}

it('pins API header commands schemas and the exact AC7 through AC9 vocabulary', function (): void {
    expect(P6GateContract::CONTRACT_MAJOR)->toBe(BuiltForCloud::API_VERSION)
        ->and(P6GateContract::CONTRACT_HEADER)->toBe(HttpContract::MAJOR_HEADER)
        ->and(P6GateContract::POSTGRES_CASES)->toBe([
            'uniqueness', 'row_lock', 'managed_transition', 'replay', 'purpose',
        ])->and(P6GateContract::LIVE_CASES)->toBe([
            'fresh_migration_and_install',
            'identical_install_rerun',
            'meta',
            'contract_major_accepted',
            'contract_major_missing_refused',
            'contract_major_malformed_refused',
            'contract_major_duplicate_field_refused',
            'contract_major_unsupported_refused',
            'fixed_purpose_admitted',
            'wrong_purpose_refused',
            'wrong_audience_refused',
            'wrong_installation_refused',
            'spoofed_client_refused',
            'cross_node_replay_refused',
            'cross_node_rotation_visible',
            'cross_node_revocation_visible',
            'single_shared_managed_refresh',
            'session_established_on_a',
            'session_accepted_on_b',
            'session_invalidated_on_a',
            'session_refused_on_b',
            'both_nodes_handled_traffic',
            'clean_teardown',
        ])->and(P6GateContract::COORDINATOR_COMMANDS)->toBe([
            'composer stan',
            'composer lint:test',
            'composer test',
            'composer test:pgsql',
            'composer test:p6c-live',
        ]);
});

it('accepts only a complete exact-archive two-node stamp', function (): void {
    $stamp = p6ValidStamp();

    P6GateStamp::assertValid($stamp);
    expect(true)->toBeTrue();
});

it('rejects incomplete stamp cells one at a time', function (string $section, string $key): void {
    $stamp = p6ValidStamp();
    unset($stamp[$section][$key]);

    expect(fn () => P6GateStamp::assertValid($stamp))->toThrow(InvalidArgumentException::class);
})->with([
    ['runtime', 'postgres'],
    ['postgres', 'run_marker_verified'],
    ['shared_runtime', 'node_b'],
    ['listeners', 'node_b'],
    ['commands', 'composer test:pgsql'],
    ['cases', 'cross_node_replay_refused'],
    ['teardown', 'database_absent'],
]);

it('rejects path branch tag and published archive evidence', function (string $source, string $version): void {
    $stamp = p6ValidStamp();
    $stamp['archive']['source'] = $source;
    $stamp['archive']['installed_version'] = $version;

    expect(fn () => P6GateStamp::assertValid($stamp))->toThrow(
        InvalidArgumentException::class,
        'exact candidate archive',
    );
})->with([
    ['path', 'dev-main'],
    ['vcs', 'dev-feat/p6c-live-gate'],
    ['dist-tag', '1.0.0'],
    ['composer-package-dist-archive', 'dev-main'],
]);

it('refuses isolated or divergent shared state between nodes', function (string $case): void {
    $stamp = p6ValidStamp();

    if ($case === 'isolated') {
        $stamp['shared_runtime']['node_a']['roles']['cache']['driver'] = 'array';
    } elseif ($case === 'driver') {
        $stamp['shared_runtime']['node_b']['roles']['session']['driver'] = 'redis';
    } elseif ($case === 'shared-wrong-database') {
        $wrong = 'bfc_p6_'.str_repeat('e', 32);
        $stamp['shared_runtime']['node_a']['database'] = $wrong;
        $stamp['shared_runtime']['node_b']['database'] = $wrong;
    } else {
        $stamp['shared_runtime']['node_b']['database'] = 'bfc_p6_'.str_repeat('e', 32);
    }

    expect(fn () => P6GateStamp::assertValid($stamp))->toThrow(InvalidArgumentException::class);
})->with(['isolated', 'driver', 'shared-wrong-database', 'database']);

it('requires an explicit relationship between separate run-owned matrix and live databases', function (string $case): void {
    $stamp = p6ValidStamp();

    if ($case === 'same-database') {
        $stamp['postgres']['matrix_database_name'] = $stamp['postgres']['database_name'];
    } else {
        $stamp['postgres']['relationship'] = 'same-database';
    }

    expect(fn () => P6GateStamp::assertValid($stamp))
        ->toThrow(InvalidArgumentException::class, 'relationship');
})->with(['same-database', 'wrong-relationship']);

it('rejects every incomplete or failed teardown observation', function (string $field): void {
    $stamp = p6ValidStamp();
    $stamp['teardown'][$field] = false;

    expect(fn () => P6GateStamp::assertValid($stamp))
        ->toThrow(InvalidArgumentException::class, 'teardown');
})->with(['bounded', 'listeners_absent', 'database_absent', 'manifest_absent']);

it('detects generated secret material and secret-shaped stamp fields', function (): void {
    $marker = 'test-created-p6-marker-'.bin2hex(random_bytes(8));
    $stamp = p6ValidStamp();
    $stamp['runtime']['php'] = $marker;

    expect(fn () => P6GateStamp::assertValid($stamp, [$marker]))
        ->toThrow(InvalidArgumentException::class, 'forbidden secret material');

    $stamp = p6ValidStamp();
    $stamp['archive']['authorization'] = 'redacted';
    expect(fn () => P6GateStamp::assertValid($stamp))->toThrow(InvalidArgumentException::class);
});

it('pins the exact P6 coordinator scripts while leaving the ordinary suite on SQLite', function (): void {
    $composer = json_decode((string) file_get_contents(__DIR__.'/../composer.json'), true, flags: JSON_THROW_ON_ERROR);

    expect($composer['scripts']['stan'])->toBe('@php tests/Support/run-p6-gate-command.php "composer stan" vendor/bin/phpstan analyse --memory-limit=512M')
        ->and($composer['scripts']['lint:test'])->toBe('@php tests/Support/run-p6-gate-command.php "composer lint:test" vendor/bin/pint --test')
        ->and($composer['scripts']['test'])->toBe('@php tests/Support/run-p6-gate-command.php "composer test" vendor/bin/pest')
        ->and($composer['scripts']['test:pgsql'])->toBe('@php tests/Support/run-p6-gate-command.php "composer test:pgsql" vendor/bin/pest --group=pgsql --fail-on-skipped --colors=never')
        ->and($composer['scripts']['test:p6c-live'])->toBe('@php tests/Live/run-p6c-live.php')
        ->and((string) file_get_contents(__DIR__.'/../README.md'))
        ->toContain('The ordinary `composer test` command remains the SQLite suite.', 'BFC_P6_COMMAND_STAMP', 'BFC_P6_LIVE_STAMP');
});
