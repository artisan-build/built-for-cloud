<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Carbon\CarbonInterface;

final readonly class CredentialAuthorizationProfile
{
    /** @param list<string> $abilities */
    public function __construct(
        public string $appPurpose,
        public BoundCredentialScope $scope,
        public CredentialAuthorizationOwnership $ownership,
        public array $abilities,
        public ?CarbonInterface $expiresAt,
        public int $codeTtlSeconds,
        public int $initialPollInterval,
    ) {}
}
