<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

/** Model-free result of a receiver-side HMAC installation. */
final readonly class InstalledHmacCredential
{
    public function __construct(
        public string $credentialId,
        public ?string $predecessorCredentialId,
        public BoundCredentialScope $scope,
        public string $algorithm = 'hmac-sha256',
    ) {}
}
