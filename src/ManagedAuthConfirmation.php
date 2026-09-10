<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use DateTimeImmutable;

final readonly class ManagedAuthConfirmation
{
    public function __construct(
        public string $scalpelsId,
        public string $membershipStatus,
        public string $connectionStatus,
        public string $role,
        public int $rosterVersion,
        public int $responseSequence,
        public DateTimeImmutable $respondedAt,
    ) {}
}
