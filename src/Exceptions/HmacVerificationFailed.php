<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Exceptions;

use ArtisanBuild\BfcClient\Exceptions\HmacVerificationFailed as SharedHmacVerificationFailed;
use RuntimeException;

/** @deprecated Catch ArtisanBuild\BfcClient\Exceptions\HmacVerificationFailed for shared verifier calls. */
final class HmacVerificationFailed extends RuntimeException
{
    private function __construct(SharedHmacVerificationFailed $failure)
    {
        parent::__construct($failure->getMessage(), previous: $failure);
        $this->reason = $failure->reason;
    }

    public readonly string $reason;

    public static function fromShared(SharedHmacVerificationFailed $failure): self
    {
        return new self($failure);
    }

    public static function malformedHeader(): self
    {
        return self::fromShared(SharedHmacVerificationFailed::malformedHeader());
    }

    public static function algorithmRejected(string $claimed): self
    {
        return self::fromShared(SharedHmacVerificationFailed::algorithmRejected($claimed));
    }

    public static function wrongAudience(): self
    {
        return self::fromShared(SharedHmacVerificationFailed::wrongAudience());
    }

    public static function audienceNotConfigured(): self
    {
        return self::fromShared(SharedHmacVerificationFailed::audienceNotConfigured());
    }

    public static function staleTimestamp(int $toleranceSeconds): self
    {
        return self::fromShared(SharedHmacVerificationFailed::staleTimestamp($toleranceSeconds));
    }

    public static function unusableKey(): self
    {
        return self::fromShared(SharedHmacVerificationFailed::unusableKey());
    }

    public static function invalidSignature(): self
    {
        return self::fromShared(SharedHmacVerificationFailed::invalidSignature());
    }

    public static function replayedNonce(): self
    {
        return self::fromShared(SharedHmacVerificationFailed::replayedNonce());
    }

    public static function rateLimited(int $ceiling): self
    {
        return self::fromShared(SharedHmacVerificationFailed::rateLimited($ceiling));
    }
}
