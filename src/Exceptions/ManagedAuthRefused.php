<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Exceptions;

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
        public readonly bool $authorityResponseReceived = false,
    ) {
        parent::__construct($message, $code, $previous);
    }
}
