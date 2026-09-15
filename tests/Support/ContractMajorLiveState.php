<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Support;

use RuntimeException;

/** Process-safe, non-secret counters shared by the contract-major live fixture. */
final class ContractMajorLiveState
{
    /** @return array<string, int> */
    public static function reset(): array
    {
        return self::mutate(static fn (array $state): array => self::empty());
    }

    public static function increment(string $counter): void
    {
        self::mutate(static function (array $state) use ($counter): array {
            if (! array_key_exists($counter, $state)) {
                throw new RuntimeException("Unknown contract-major live counter [{$counter}].");
            }

            $state[$counter]++;

            return $state;
        });
    }

    /** @return array<string, int> */
    public static function snapshot(): array
    {
        return self::mutate(static fn (array $state): array => $state);
    }

    /** @return array<string, int> */
    private static function empty(): array
    {
        return [
            'authentication_entries' => 0,
            'credential_resolver_invocations' => 0,
            'replay_store_reads' => 0,
            'replay_store_writes' => 0,
            'cache_actions' => 0,
            'queue_actions' => 0,
            'domain_actions' => 0,
        ];
    }

    /**
     * @param  callable(array<string, int>): array<string, int>  $callback
     * @return array<string, int>
     */
    private static function mutate(callable $callback): array
    {
        $path = getenv('BFC_CONTRACT_MAJOR_STATE');

        if (! is_string($path) || $path === '') {
            throw new RuntimeException('BFC_CONTRACT_MAJOR_STATE is required by the live fixture.');
        }

        $file = fopen($path, 'c+');

        if ($file === false || ! flock($file, LOCK_EX)) {
            throw new RuntimeException('Could not lock the contract-major live state.');
        }

        try {
            rewind($file);
            $contents = stream_get_contents($file);
            $decoded = is_string($contents) && $contents !== '' ? json_decode($contents, true) : null;
            $state = is_array($decoded) ? array_replace(self::empty(), $decoded) : self::empty();
            $state = $callback($state);
            $encoded = json_encode($state, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

            rewind($file);

            if (! ftruncate($file, 0) || fwrite($file, $encoded) === false || ! fflush($file)) {
                throw new RuntimeException('Could not persist the contract-major live state.');
            }

            return $state;
        } finally {
            flock($file, LOCK_UN);
            fclose($file);
        }
    }
}
