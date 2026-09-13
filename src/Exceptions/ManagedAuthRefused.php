<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Exceptions;

use ArtisanBuild\BuiltForCloud\ManagedAuthRefusalReason;
use RuntimeException;
use Throwable;

final class ManagedAuthRefused extends RuntimeException
{
    public function __construct(
        string $message = '',
        int $code = 0,
        ?Throwable $previous = null,
        public readonly ?int $retryAfterSeconds = null,
        public readonly bool $recordsFailedAttempt = false,
        public readonly ?ManagedAuthRefusalReason $reason = null,
    ) {
        parent::__construct($message, $code, $previous);
    }

    public static function because(ManagedAuthRefusalReason $reason, ?Throwable $previous = null): self
    {
        return new self($reason->value, previous: $previous, reason: $reason);
    }
}
