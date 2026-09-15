<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use InvalidArgumentException;
use JsonException;
use RuntimeException;

/** Records exact-SHA coordinator command outcomes for the final live stamp. */
final class P6GateCommandLedger
{
    public const string SCHEMA = 'bfc.p6.commands.v1';

    public static function record(string $path, string $candidateSha, string $command, int $exitCode): void
    {
        self::assertCandidateSha($candidateSha);

        if (! in_array($command, P6GateContract::COORDINATOR_COMMANDS, true)) {
            throw new InvalidArgumentException("Unknown P6c coordinator command [{$command}].");
        }

        $file = fopen($path, 'c+b');
        if ($file === false || ! flock($file, LOCK_EX)) {
            throw new RuntimeException('The P6c command ledger could not be locked.');
        }

        try {
            $contents = stream_get_contents($file);
            $ledger = is_string($contents) && trim($contents) !== ''
                ? self::decode($contents)
                : ['schema' => self::SCHEMA, 'candidate_sha' => $candidateSha, 'commands' => []];

            if (($ledger['candidate_sha'] ?? null) !== $candidateSha) {
                throw new RuntimeException('The P6c command ledger belongs to a different candidate SHA.');
            }

            if (array_keys($ledger) !== ['schema', 'candidate_sha', 'commands']
                || ($ledger['schema'] ?? null) !== self::SCHEMA) {
                throw new RuntimeException('The P6c command ledger identity or schema is invalid.');
            }

            $commands = $ledger['commands'] ?? null;
            if (! is_array($commands)) {
                throw new RuntimeException('The P6c command ledger command map is invalid.');
            }

            self::assertRecordedSequence($commands);
            $recorded = array_keys($commands);
            if (array_key_exists($command, $commands)) {
                $current = $commands[$command];
                if (! is_array($current) || end($recorded) !== $command || ($current['verdict'] ?? null) !== 'fail') {
                    throw new RuntimeException('Only the current failed P6c command may be retried.');
                }
            } else {
                $expected = P6GateContract::COORDINATOR_COMMANDS[count($recorded)] ?? null;
                $lastKey = array_key_last($commands);
                $last = $lastKey === null ? null : $commands[$lastKey];
                if ($command !== $expected || (is_array($last) && ($last['verdict'] ?? null) === 'fail')) {
                    throw new RuntimeException('The P6c coordinator command was recorded out of contract order.');
                }
            }

            $commands[$command] = [
                'exit_code' => $exitCode,
                'verdict' => $exitCode === 0 ? 'pass' : 'fail',
            ];
            $ledger['commands'] = $commands;
            $encoded = json_encode($ledger, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)."\n";

            rewind($file);
            if (! ftruncate($file, 0) || fwrite($file, $encoded) !== strlen($encoded) || ! fflush($file)) {
                throw new RuntimeException('The P6c command ledger could not be persisted.');
            }
            chmod($path, 0600);
        } finally {
            flock($file, LOCK_UN);
            fclose($file);
        }
    }

    /** @return array<string, array{exit_code: int, verdict: string}> */
    public static function completedForLiveRunner(string $path, string $candidateSha): array
    {
        self::assertCandidateSha($candidateSha);
        $contents = @file_get_contents($path);

        if (! is_string($contents)) {
            throw new RuntimeException('The observed P6c command ledger is required by the live runner.');
        }

        $ledger = self::decode($contents);
        if (array_keys($ledger) !== ['schema', 'candidate_sha', 'commands']
            || ($ledger['schema'] ?? null) !== self::SCHEMA
            || ! is_array($ledger['commands'] ?? null)) {
            throw new RuntimeException('The P6c command ledger identity or schema is invalid.');
        }

        if (($ledger['candidate_sha'] ?? null) !== $candidateSha) {
            throw new RuntimeException('The P6c command ledger belongs to a different candidate SHA.');
        }

        $results = $ledger['commands'];
        $expected = array_slice(P6GateContract::COORDINATOR_COMMANDS, 0, -1);
        if (array_keys($results) !== $expected) {
            throw new RuntimeException('The observed P6c command history is incomplete or out of contract order.');
        }

        foreach ($results as $command => $result) {
            if (! is_array($result)
                || array_keys($result) !== ['exit_code', 'verdict']
                || ($result['exit_code'] ?? null) !== 0
                || ($result['verdict'] ?? null) !== 'pass') {
                throw new RuntimeException("The observed P6c command [{$command}] has not passed on this candidate.");
            }

        }

        return $results;
    }

    /** @return array<string, mixed> */
    private static function decode(string $contents): array
    {
        try {
            $decoded = json_decode($contents, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new RuntimeException('The P6c command ledger is not valid JSON.', previous: $exception);
        }

        return is_array($decoded) && ! array_is_list($decoded)
            ? $decoded
            : throw new RuntimeException('The P6c command ledger is invalid.');
    }

    private static function assertCandidateSha(string $candidateSha): void
    {
        if (preg_match('/^[a-f0-9]{40}$/D', $candidateSha) !== 1) {
            throw new InvalidArgumentException('The P6c candidate SHA is invalid.');
        }
    }

    /** @param array<string, mixed> $commands */
    private static function assertRecordedSequence(array $commands): void
    {
        $keys = array_keys($commands);
        if ($keys !== array_slice(P6GateContract::COORDINATOR_COMMANDS, 0, count($keys))) {
            throw new RuntimeException('The P6c command ledger history is out of contract order.');
        }

        foreach ($commands as $result) {
            if (! is_array($result)
                || array_keys($result) !== ['exit_code', 'verdict']
                || ! is_int($result['exit_code'] ?? null)
                || ($result['verdict'] ?? null) !== (($result['exit_code'] ?? null) === 0 ? 'pass' : 'fail')) {
                throw new RuntimeException('The P6c command ledger contains an invalid observed result.');
            }
        }
    }
}
