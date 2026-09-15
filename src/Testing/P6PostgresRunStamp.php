<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use JsonException;
use RuntimeException;

/** Validates the observed PostgreSQL-lane evidence consumed by the live gate. */
final class P6PostgresRunStamp
{
    /** @return array<string, mixed> */
    public static function read(string $path, string $candidateSha): array
    {
        $contents = @file_get_contents($path);

        try {
            $stamp = is_string($contents) ? json_decode($contents, true, flags: JSON_THROW_ON_ERROR) : null;
        } catch (JsonException $exception) {
            throw new RuntimeException('The completed observed PostgreSQL stamp is invalid.', previous: $exception);
        }

        if (! is_array($stamp)
            || array_keys($stamp) !== ['schema', 'candidate_sha', 'database_name', 'run_marker_verified', 'cases', 'teardown']
            || ($stamp['schema'] ?? null) !== 'bfc.p6.postgres.v2'
            || ($stamp['candidate_sha'] ?? null) !== $candidateSha
            || ! is_string($stamp['database_name'] ?? null)
            || ($stamp['run_marker_verified'] ?? null) !== true
            || ! is_array($stamp['cases'] ?? null)
            || array_keys($stamp['cases']) !== P6GateContract::POSTGRES_CASES
            || array_values(array_unique($stamp['cases'])) !== ['pass']
            || ! is_array($stamp['teardown'] ?? null)
            || array_keys($stamp['teardown']) !== [
                'database_absent', 'manifest_absent', 'marker_verified', 'already_dropped', 'verdict',
            ]
            || ($stamp['teardown']['database_absent'] ?? null) !== true
            || ($stamp['teardown']['manifest_absent'] ?? null) !== true
            || ($stamp['teardown']['marker_verified'] ?? null) !== true
            || ($stamp['teardown']['already_dropped'] ?? null) !== false
            || ($stamp['teardown']['verdict'] ?? null) !== 'pass') {
            throw new RuntimeException('The completed observed PostgreSQL stamp is required by the P6c live runner.');
        }

        PostgresRunIdentity::assertDatabaseName($stamp['database_name']);

        return $stamp;
    }
}
