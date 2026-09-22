<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Console\ConsoleReturnTo;

final class ManagedReturnTo
{
    private const int MAX_DECODE_ROUNDS = 4;

    public static function relative(mixed $candidate): ?string
    {
        if (! is_string($candidate)
            || $candidate === ''
            || strlen($candidate) > ConsoleReturnTo::MAX_LENGTH
            || str_contains($candidate, '#')) {
            return null;
        }

        $cut = strpos($candidate, '?');
        $path = $cut === false ? $candidate : substr($candidate, 0, $cut);
        $query = $cut === false ? null : substr($candidate, $cut + 1);
        $canonicalPath = ConsoleReturnTo::canonicalPath($path);

        if ($canonicalPath === null || strpbrk($canonicalPath, '?#') !== false) {
            return null;
        }

        return $query === null || self::queryIsSafe($query) ? $candidate : null;
    }

    /** @param list<mixed> $candidates */
    public static function firstRelative(array $candidates): string
    {
        foreach ($candidates as $candidate) {
            $relative = self::relative($candidate);

            if ($relative !== null) {
                return $relative;
            }
        }

        return '/';
    }

    private static function queryIsSafe(string $query): bool
    {
        $form = $query;

        for ($round = 0; $round <= self::MAX_DECODE_ROUNDS; $round++) {
            $unsafe = $round === 0
                ? preg_match('/[^\x21-\x7E]|\\\\/', $form) !== 0
                : preg_match('/[^\x20-\x7E]|\\\\/', $form) !== 0;

            if ($unsafe) {
                return false;
            }

            $decoded = rawurldecode($form);

            if ($decoded === $form) {
                return true;
            }

            $form = $decoded;
        }

        return false;
    }
}
