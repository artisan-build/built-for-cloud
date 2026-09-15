<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Exceptions;

use Carbon\CarbonImmutable;
use RuntimeException;
use Throwable;

/** Source activation committed but receiver cutover still needs recovery. */
final class CrossStoreCutoverIncomplete extends RuntimeException
{
    public function __construct(
        public readonly string $predecessorCredentialId,
        public readonly string $replacementCredentialId,
        public readonly CarbonImmutable $authoritativeExpiry,
        ?Throwable $previous = null,
    ) {
        parent::__construct(
            'The issuer HMAC activation succeeded, but receiver cutover is incomplete; recover through authenticated cutover status.',
            0,
            $previous,
        );
    }
}
