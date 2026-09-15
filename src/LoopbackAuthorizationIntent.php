<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

final readonly class LoopbackAuthorizationIntent
{
    public function __construct(
        public string $authorizationId,
        public string $appPurpose,
        public string $redirectUri,
        public string $state,
        public MintedSecret $browserNonce,
    ) {}
}
