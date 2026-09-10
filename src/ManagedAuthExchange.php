<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use DateTimeImmutable;

final readonly class ManagedAuthExchange
{
    public function __construct(
        public string $scalpelsId,
        public string $membershipId,
        public string $membershipStatus,
        public string $connectionStatus,
        public string $role,
        public string $displayName,
        public string $contactEmail,
        public bool $contactEmailVerified,
        public int $rosterVersion,
        public int $responseSequence,
        public DateTimeImmutable $respondedAt,
    ) {}
}
