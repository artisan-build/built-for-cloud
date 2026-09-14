<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use InvalidArgumentException;

/** Validates complete, exact-archive, secret-free P6c evidence before it can pass. */
final class P6GateStamp
{
    /** @param array<string, mixed> $stamp
     * @param  list<string>  $forbiddenMaterials
     */
    public static function assertValid(array $stamp, array $forbiddenMaterials = []): void
    {
        self::assertExactKeys($stamp, [
            'schema',
            'candidate_sha',
            'archive',
            'runtime',
            'postgres',
            'shared_runtime',
            'listeners',
            'commands',
            'cases',
            'teardown',
            'overall_verdict',
            'exit_code',
        ], 'stamp');

        if ($stamp['schema'] !== P6GateContract::SCHEMA
            || ! is_string($stamp['candidate_sha'])
            || preg_match('/^[a-f0-9]{40}$/D', $stamp['candidate_sha']) !== 1
            || $stamp['overall_verdict'] !== 'pass'
            || $stamp['exit_code'] !== 0) {
            throw new InvalidArgumentException('The P6c stamp identity or verdict is invalid.');
        }

        self::assertArchive($stamp['archive'], $stamp['candidate_sha']);
        self::assertRuntime($stamp['runtime']);
        $liveDatabase = self::assertPostgres($stamp['postgres']);
        self::assertSharedRuntime($stamp['shared_runtime'], $liveDatabase);
        self::assertListeners($stamp['listeners']);
        self::assertCommands($stamp['commands']);
        self::assertCases($stamp['cases']);
        self::assertTeardown($stamp['teardown']);
        self::assertSecretFree($stamp, $forbiddenMaterials);
    }

    private static function assertArchive(mixed $archive, string $sha): void
    {
        if (! is_array($archive)) {
            throw new InvalidArgumentException('The P6c archive evidence is absent.');
        }

        self::assertExactKeys($archive, ['source', 'candidate_sha', 'sha256', 'installed_version'], 'archive');
        $source = $archive['source'] ?? null;

        if ($source !== 'composer-package-dist-archive'
            || ($archive['candidate_sha'] ?? null) !== $sha
            || ! is_string($archive['sha256'] ?? null)
            || preg_match('/^[a-f0-9]{64}$/D', $archive['sha256']) !== 1
            || ! is_string($archive['installed_version'] ?? null)
            || preg_match('/^0\.0\.0\+p6c\.[a-f0-9]{40}$/D', $archive['installed_version']) !== 1) {
            throw new InvalidArgumentException('The package was not proven from the exact candidate archive.');
        }
    }

    private static function assertRuntime(mixed $runtime): void
    {
        if (! is_array($runtime)) {
            throw new InvalidArgumentException('The P6c runtime evidence is absent.');
        }

        self::assertExactKeys($runtime, ['php', 'laravel', 'postgres'], 'runtime');
        foreach ($runtime as $version) {
            if (! is_string($version) || $version === '') {
                throw new InvalidArgumentException('A P6c runtime version is absent.');
            }
        }
    }

    private static function assertPostgres(mixed $postgres): string
    {
        if (! is_array($postgres)) {
            throw new InvalidArgumentException('The P6c PostgreSQL evidence is absent.');
        }

        self::assertExactKeys($postgres, [
            'database_name',
            'matrix_database_name',
            'relationship',
            'run_marker_verified',
            'cases',
        ], 'postgres');
        $database = is_string($postgres['database_name'] ?? null) ? $postgres['database_name'] : '';
        $matrixDatabase = is_string($postgres['matrix_database_name'] ?? null) ? $postgres['matrix_database_name'] : '';
        PostgresRunIdentity::assertDatabaseName($database);
        PostgresRunIdentity::assertDatabaseName($matrixDatabase);

        if (($postgres['run_marker_verified'] ?? null) !== true) {
            throw new InvalidArgumentException('The P6c PostgreSQL run marker was not verified.');
        }

        if (($postgres['relationship'] ?? null) !== 'separate-run-owned-databases'
            || $database === $matrixDatabase) {
            throw new InvalidArgumentException('The PostgreSQL matrix and live database relationship is invalid.');
        }

        self::assertVerdicts($postgres['cases'] ?? null, P6GateContract::POSTGRES_CASES, 'PostgreSQL');

        return $database;
    }

    private static function assertSharedRuntime(mixed $shared, string $liveDatabase): void
    {
        if (! is_array($shared)) {
            throw new InvalidArgumentException('The P6c shared runtime evidence is absent.');
        }

        self::assertExactKeys($shared, ['node_a', 'node_b'], 'shared_runtime');
        $a = self::sharedIdentity($shared['node_a'] ?? null);
        $b = self::sharedIdentity($shared['node_b'] ?? null);
        $a->assertSameAs($b);

        if ($a->database !== $liveDatabase) {
            throw new InvalidArgumentException('The HTTP nodes do not use the stamped live PostgreSQL database.');
        }
    }

    private static function assertListeners(mixed $listeners): void
    {
        if (! is_array($listeners) || array_keys($listeners) !== ['node_a', 'node_b']) {
            throw new InvalidArgumentException('The P6c listener inventory is incomplete.');
        }

        $ports = [];
        foreach ($listeners as $listener) {
            if (! is_array($listener)) {
                throw new InvalidArgumentException('A P6c listener identity is absent.');
            }

            self::assertExactKeys($listener, ['pid', 'port', 'address', 'identity_verified'], 'listener');
            if (! is_int($listener['pid'] ?? null)
                || $listener['pid'] < 1
                || ! is_int($listener['port'] ?? null)
                || $listener['port'] < 1
                || $listener['port'] > 65535
                || ($listener['address'] ?? null) !== '127.0.0.1:'.$listener['port']
                || ($listener['identity_verified'] ?? null) !== true) {
                throw new InvalidArgumentException('A P6c listener identity is invalid.');
            }

            $ports[] = $listener['port'];
        }

        if (count(array_unique($ports)) !== 2) {
            throw new InvalidArgumentException('The P6c listener ports are not distinct.');
        }
    }

    private static function assertCommands(mixed $commands): void
    {
        if (! is_array($commands) || array_keys($commands) !== P6GateContract::COORDINATOR_COMMANDS) {
            throw new InvalidArgumentException('The P6c command inventory is incomplete or out of order.');
        }

        foreach ($commands as $command => $result) {
            if (! is_array($result)) {
                throw new InvalidArgumentException("The P6c command result for {$command} is absent.");
            }
            self::assertExactKeys($result, ['exit_code', 'verdict'], 'command');
            if (($result['exit_code'] ?? null) !== 0 || ($result['verdict'] ?? null) !== 'pass') {
                throw new InvalidArgumentException("The P6c command {$command} did not pass.");
            }
        }
    }

    private static function assertCases(mixed $cases): void
    {
        self::assertVerdicts($cases, P6GateContract::LIVE_CASES, 'live');
    }

    private static function assertTeardown(mixed $teardown): void
    {
        if (! is_array($teardown)) {
            throw new InvalidArgumentException('The P6c teardown evidence is absent.');
        }

        self::assertExactKeys($teardown, ['bounded', 'listeners_absent', 'database_absent', 'manifest_absent', 'verdict'], 'teardown');
        if (($teardown['bounded'] ?? null) !== true
            || ($teardown['listeners_absent'] ?? null) !== true
            || ($teardown['database_absent'] ?? null) !== true
            || ($teardown['manifest_absent'] ?? null) !== true
            || ($teardown['verdict'] ?? null) !== 'pass') {
            throw new InvalidArgumentException('The P6c teardown did not pass completely.');
        }
    }

    /**
     * @param  list<string>  $expected
     */
    private static function assertVerdicts(mixed $verdicts, array $expected, string $label): void
    {
        if (! is_array($verdicts) || array_keys($verdicts) !== $expected) {
            throw new InvalidArgumentException("The {$label} case inventory is incomplete or out of order.");
        }

        foreach ($verdicts as $case => $verdict) {
            if ($verdict !== 'pass') {
                throw new InvalidArgumentException("The {$label} case {$case} did not pass.");
            }
        }
    }

    private static function sharedIdentity(mixed $identity): SharedRuntimeIdentity
    {
        if (! is_array($identity)) {
            throw new InvalidArgumentException('A P6c shared runtime identity is absent.');
        }

        self::assertExactKeys($identity, ['database', 'roles'], 'shared runtime identity');

        return new SharedRuntimeIdentity(
            is_string($identity['database'] ?? null) ? $identity['database'] : '',
            is_array($identity['roles'] ?? null) ? $identity['roles'] : [],
        );
    }

    /**
     * @param  array<string, mixed>  $value
     * @param  list<string>  $expected
     */
    private static function assertExactKeys(array $value, array $expected, string $label): void
    {
        if (array_keys($value) !== $expected) {
            throw new InvalidArgumentException("The P6c {$label} schema is incomplete or contains unknown fields.");
        }
    }

    /**
     * @param  array<string, mixed>  $stamp
     * @param  list<string>  $forbiddenMaterials
     */
    private static function assertSecretFree(array $stamp, array $forbiddenMaterials): void
    {
        $encoded = json_encode($stamp, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

        foreach ($forbiddenMaterials as $material) {
            if ($material !== '' && str_contains($encoded, $material)) {
                throw new InvalidArgumentException('The P6c stamp contains forbidden secret material.');
            }
        }

        $keys = [];
        array_walk_recursive($stamp, static function (mixed $value, mixed $key) use (&$keys): void {
            if (is_string($key)) {
                $keys[] = strtolower($key);
            }
        });

        foreach ($keys as $key) {
            if (preg_match('/(?:secret|password|authorization|cookie|session_material|run_marker_value)/', $key) === 1) {
                throw new InvalidArgumentException('The P6c stamp contains a secret-bearing field.');
            }
        }
    }
}
