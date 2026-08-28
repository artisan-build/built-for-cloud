<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Exceptions;

use ArtisanBuild\BuiltForCloud\Hmac\HmacEnvelope;
use ArtisanBuild\BuiltForCloud\Http\Middleware\VerifyHmacSignature;
use RuntimeException;

/**
 * A presented hmac signature did not verify. `$reason` is a bounded
 * machine-readable code for LOGS AND TESTS — the HTTP surface
 * ({@see VerifyHmacSignature})
 * deliberately collapses every reason into one uniform 401, so a caller
 * probing the verifier cannot distinguish "unknown key" from "wrong
 * subject" from "bad signature". Messages never carry key material,
 * signatures, or the presented header.
 */
final class HmacVerificationFailed extends RuntimeException
{
    private function __construct(string $message, public readonly string $reason)
    {
        parent::__construct($message);
    }

    public static function malformedHeader(): self
    {
        return new self('The signature header does not fit the documented wire form.', 'malformed_header');
    }

    /**
     * The algorithm pin (SEC-V3-07: no alg confusion): the verifier
     * speaks hmac-sha256 and nothing else — no negotiation, no downgrade.
     */
    public static function algorithmRejected(string $claimed): self
    {
        return new self(sprintf(
            'The signature claims algorithm "%s"; this verifier pins %s and negotiates nothing.',
            $claimed,
            HmacEnvelope::ALGORITHM,
        ), 'algorithm_rejected');
    }

    public static function wrongAudience(): self
    {
        return new self('The signed audience is not this verifier\'s audience.', 'wrong_audience');
    }

    public static function staleTimestamp(int $toleranceSeconds): self
    {
        return new self(sprintf(
            'The signed timestamp is outside the ±%d second acceptance bound.',
            $toleranceSeconds,
        ), 'stale_timestamp');
    }

    /**
     * ONE answer for every key-selection failure — unknown id, another
     * subject's id, a pending key, a revoked/expired key: the verifier
     * selects on (server-derived subject, key id, active-or-grace) and a
     * miss is a miss, never an oracle for WHICH constraint failed.
     */
    public static function unusableKey(): self
    {
        return new self('No usable signing key matches the presented key id for this subject.', 'unusable_key');
    }

    public static function invalidSignature(): self
    {
        return new self('The signature does not match the canonical envelope.', 'invalid_signature');
    }

    public static function replayedNonce(): self
    {
        return new self('The signed nonce was already consumed inside the replay window.', 'replayed_nonce');
    }
}
