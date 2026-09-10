<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use DateTimeImmutable;

final readonly class ManagedHandoffAuthorization
{
    public function __construct(
        public string $url,
        public DateTimeImmutable $expiresAt,
    ) {}
}
