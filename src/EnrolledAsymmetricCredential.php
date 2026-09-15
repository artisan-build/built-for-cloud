<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

final readonly class EnrolledAsymmetricCredential
{
    public function __construct(
        public string $credentialId,
        public string $appPurpose,
        public Subject $subject,
        public string $installation,
        public string $application,
        public string $audience,
        public CredentialAlgorithm $algorithm,
    ) {}
}
