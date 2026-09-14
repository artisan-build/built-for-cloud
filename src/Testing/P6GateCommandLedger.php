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

            $commands = $ledger['commands'] ?? null;
            if (! is_array($commands)) {
                throw new RuntimeException('The P6c command ledger command map is invalid.');
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

        $results = [];
        foreach (array_slice(P6GateContract::COORDINATOR_COMMANDS, 0, -1) as $command) {
            $result = $ledger['commands'][$command] ?? null;
            if (! is_array($result)
                || array_keys($result) !== ['exit_code', 'verdict']
                || ($result['exit_code'] ?? null) !== 0
                || ($result['verdict'] ?? null) !== 'pass') {
                throw new RuntimeException("The observed P6c command [{$command}] has not passed on this candidate.");
            }

            $results[$command] = ['exit_code' => 0, 'verdict' => 'pass'];
        }

        $unknown = array_diff(array_keys($ledger['commands']), P6GateContract::COORDINATOR_COMMANDS);
        if ($unknown !== []) {
            throw new RuntimeException('The P6c command ledger contains an unknown command.');
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
}
