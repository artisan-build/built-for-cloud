<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

/** Model-free identity returned by exact-scope HMAC verification. */
final readonly class VerifiedHmacCredential
{
    public function __construct(
        public string $credentialId,
        public BoundCredentialScope $scope,
        public string $algorithm = 'hmac-sha256',
    ) {}
}
