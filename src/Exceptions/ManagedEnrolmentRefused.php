<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Exceptions;

use ArtisanBuild\BuiltForCloud\ManagedEnrolmentConflict;
use RuntimeException;

/**
 * A bounded managed-enrolment refusal (P1): the conflict vocabulary
 * every route's 409 draws from, plus whether this surface also carries
 * it as the disconnect `reason` field (ruling A1). Thrown inside the
 * verb's transaction so the refusal and the rollback are one act.
 */
final class ManagedEnrolmentRefused extends RuntimeException
{
    public function __construct(
        public readonly ManagedEnrolmentConflict $conflict,
        public readonly bool $withReason = false,
    ) {
        parent::__construct($conflict->value);
    }
}
