<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

final readonly class ManagedAuthHighWater
{
    public function __construct(
        public int $rosterVersion,
        public int $responseSequence,
    ) {}
}
