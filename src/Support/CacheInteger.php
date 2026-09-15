<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Support;

/** @internal */
final class CacheInteger
{
    /**
     * Read the canonical non-negative integer shape shared cache drivers use.
     */
    public static function parse(mixed $value): ?int
    {
        if (is_int($value)) {
            return $value >= 0 ? $value : null;
        }

        if (! is_string($value) || preg_match('/\A(?:0|[1-9]\d*)\z/D', $value) !== 1) {
            return null;
        }

        $integer = (int) $value;

        return (string) $integer === $value ? $integer : null;
    }
}
