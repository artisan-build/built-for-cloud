<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Carbon\CarbonImmutable;

/** Model-free result of applying the issuer's cutover deadline locally. */
final readonly class CutOverImportedHmacResult
{
    public function __construct(
        public string $predecessorCredentialId,
        public string $replacementCredentialId,
        public BoundCredentialScope $scope,
        public CarbonImmutable $predecessorExpiresAt,
        public string $algorithm = 'hmac-sha256',
    ) {}
}
