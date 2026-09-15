<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use RuntimeException;

/** Deadline-bounded polling that yields through stream_select rather than sleeps. */
final class BoundedWait
{
    public static function until(callable $condition, float $timeoutSeconds, string $timeoutMessage): mixed
    {
        if ($timeoutSeconds <= 0 || $timeoutSeconds > 300) {
            throw new RuntimeException('The bounded wait deadline is invalid.');
        }

        $pair = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);

        if (! is_array($pair)) {
            throw new RuntimeException('The bounded wait yield socket could not be created.');
        }

        $deadline = hrtime(true) + (int) ($timeoutSeconds * 1_000_000_000);

        try {
            do {
                $result = $condition();

                if ($result !== false && $result !== null) {
                    return $result;
                }

                $remaining = $deadline - hrtime(true);
                if ($remaining <= 0) {
                    break;
                }

                $read = [$pair[0]];
                $write = null;
                $except = null;
                $microseconds = min(20_000, max(1, (int) ceil($remaining / 1000)));
                stream_select($read, $write, $except, 0, $microseconds);
            } while (hrtime(true) < $deadline);
        } finally {
            fclose($pair[0]);
            fclose($pair[1]);
        }

        throw new RuntimeException($timeoutMessage);
    }
}
