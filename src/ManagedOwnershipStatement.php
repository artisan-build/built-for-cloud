<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use DateTimeImmutable;

final readonly class ManagedOwnershipStatement
{
    public function __construct(
        public ?string $requestedSeatedOwnerScalpelsId,
        public ManagedOwnershipSubject $owner,
        public ?ManagedOwnershipSubject $seatedOwner,
        public int $rosterVersion,
        public int $responseSequence,
        public DateTimeImmutable $respondedAt,
    ) {}
}
