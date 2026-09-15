<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

final readonly class CredentialAuthorizationDecision
{
    public function __construct(
        public string $authorizationId,
        public CredentialAuthorizationStatus $status,
        public ?MintedSecret $authorizationCode = null,
        public ?string $redirectUri = null,
        public ?string $state = null,
    ) {}
}
