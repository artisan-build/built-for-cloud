<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

final readonly class ManagedOwnershipSubject
{
    public function __construct(
        public string $scalpelsId,
        public string $membershipStatus,
        public string $role,
    ) {}
}
