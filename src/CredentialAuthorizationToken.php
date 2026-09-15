<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Carbon\CarbonInterface;

final readonly class CredentialAuthorizationToken
{
    public function __construct(
        public MintedSecret $accessToken,
        public string $credentialId,
        public string $appPurpose,
        public ?CarbonInterface $expiresAt,
    ) {}
}
