<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

final readonly class AsymmetricVerificationKey
{
    public function __construct(
        public string $credentialId,
        public string $publicKey,
        public CredentialAlgorithm $algorithm,
    ) {}
}
