<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Illuminate\Http\Request;

/**
 * The provider half of the `X-BfC-Client-Id` contract shipped by artisan-build/bfc-client.
 *
 * The value is an OPAQUE identifier: compare it byte-wise, store it verbatim, and never
 * treat it as a credential. It grants nothing on its own.
 *
 * One deliberate server-side narrowing of the shipped wire contract: a NUL byte is rejected.
 * PostgreSQL truncates a bound value at the first NUL silently rather than erroring, so
 * accepting one would mean storing an identity that differs from the one presented -- and
 * would let two distinct identities collide on one row. We cannot honour store-verbatim for
 * it on every driver, so we drop it the way we drop any other value we will not accept.
 */
final class ClientIdentity
{
    public const HEADER = 'X-BfC-Client-Id';

    public const MAX_BYTES = 255;

    public static function isValid(string $value): bool
    {
        return self::rejectionReason($value) === null;
    }

    /**
     * Why a value violates the contract, or null when it does not.
     *
     * Never include the value itself in the reason: it is attacker-controlled.
     */
    public static function rejectionReason(string $value): ?string
    {
        $bytes = strlen($value);

        if ($bytes < 1) {
            return 'empty value';
        }

        if ($bytes > self::MAX_BYTES) {
            return 'longer than '.self::MAX_BYTES.' bytes';
        }

        if (str_contains($value, "\r") || str_contains($value, "\n")) {
            return 'contains a line break';
        }

        if (str_contains($value, "\0")) {
            return 'contains a null byte';
        }

        if (! mb_check_encoding($value, 'UTF-8')) {
            return 'not valid UTF-8';
        }

        return null;
    }

    /**
     * The verbatim header value, or null when it is absent, repeated, or invalid.
     */
    public static function fromRequest(Request $request): ?string
    {
        $values = $request->headers->all(self::HEADER);

        if (count($values) !== 1) {
            return null;
        }

        $value = $values[array_key_first($values)];

        if (! is_string($value)) {
            return null;
        }

        return self::isValid($value) ? $value : null;
    }
}
