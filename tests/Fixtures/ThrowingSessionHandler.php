<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use RuntimeException;
use SessionHandlerInterface;

/**
 * A session handler whose `destroy()` can be armed to fail — the "the
 * session store is unreachable" condition, on demand.
 *
 * It is armed rather than always-failing so a test can let a redemption
 * write and regenerate its session normally and then fail only the
 * COMPENSATION's `invalidate()`. That ordering is the whole point: the
 * failure under test has to be something other than the store, so the
 * test can tell which exception the caller ends up with.
 *
 * Everything else is an in-memory session store.
 */
final class ThrowingSessionHandler implements SessionHandlerInterface
{
    /** Whether `destroy()` should throw on its next call. */
    public static bool $failOnDestroy = false;

    /** @var array<string, string> */
    private array $sessions = [];

    public static function reset(): void
    {
        self::$failOnDestroy = false;
    }

    public function open($path, $name): bool
    {
        return true;
    }

    public function close(): bool
    {
        return true;
    }

    public function read($id): string
    {
        return $this->sessions[$id] ?? '';
    }

    public function write($id, $data): bool
    {
        $this->sessions[$id] = $data;

        return true;
    }

    public function destroy($id): bool
    {
        if (self::$failOnDestroy) {
            throw new RuntimeException('the session store is unreachable');
        }

        unset($this->sessions[$id]);

        return true;
    }

    public function gc($max_lifetime): int
    {
        return 0;
    }
}
