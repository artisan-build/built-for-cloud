<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Carbon\CarbonInterface;

/**
 * What the activate verb returns (PRD 1.21, SEC-V3-01): the now-active
 * key's summary — never a secret; activation reveals nothing, the key was
 * already delivered — plus, when the activation completed a rotation
 * cutover, the superseded row it retired into grace and the LATEST moment
 * that grace ends (the superseded row's own earlier expiry, if any, still
 * wins — retirement never extends a life).
 */
final readonly class ActivationResult
{
    public function __construct(
        public CredentialSummary $summary,
        public ?string $supersededId = null,
        public ?CarbonInterface $graceEndsAt = null,
    ) {}
}
