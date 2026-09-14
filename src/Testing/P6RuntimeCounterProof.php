<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use InvalidArgumentException;
use RuntimeException;

/** Proves exact shared counter deltas around one bounded live transition. */
final class P6RuntimeCounterProof
{
    public static function counterForRequest(string $method, string $path): ?string
    {
        return match (true) {
            $path === '_bfc-p6c/mcp' => 'mcp',
            $method === 'POST' && preg_match('#^bfc/credentials/[^/]+/rotate$#D', $path) === 1 => 'credential_rotate',
            $method === 'DELETE' && preg_match('#^bfc/credentials/[^/]+$#D', $path) === 1 => 'credential_revoke',
            $method === 'POST' && $path === 'bfc/login' => 'session_establish',
            $method === 'GET' && $path === '_bfc-p6c/session' => 'session_accept',
            $method === 'POST' && $path === '_bfc-p6c/session/invalidate' => 'session_invalidate',
            $method === 'POST' && str_starts_with($path, '_bfc-p6c/managed-refresh/') => 'managed_refresh',
            default => null,
        };
    }

    /**
     * @param  array<string, int>  $before
     * @param  array<string, int>  $after
     * @param  non-empty-array<string, positive-int>  $expectedDeltas
     */
    public static function assertDeltas(array $before, array $after, array $expectedDeltas): void
    {
        if ($expectedDeltas === []) {
            throw new InvalidArgumentException('A P6c runtime counter proof requires expected deltas.');
        }

        foreach ($expectedDeltas as $counter => $delta) {
            if ($counter === '' || $delta < 1) {
                throw new InvalidArgumentException('A P6c runtime counter expectation is invalid.');
            }

            $observed = ($after[$counter] ?? 0) - ($before[$counter] ?? 0);
            if ($observed !== $delta) {
                throw new RuntimeException("The P6c runtime counter [{$counter}] did not advance exactly {$delta} time(s).");
            }
        }
    }
}
