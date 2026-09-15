<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Carbon\CarbonInterface;

final readonly class BoundBearerCredential
{
    /** @param list<string> $abilities */
    public function __construct(
        public string $id,
        public BoundCredentialScope $scope,
        public CredentialAuthorizationOwnership $ownership,
        public array $abilities,
        public ?string $userId,
        public ?CarbonInterface $expiresAt,
    ) {}

    public function hasAbility(string $ability): bool
    {
        return in_array($ability, $this->abilities, true);
    }
}
