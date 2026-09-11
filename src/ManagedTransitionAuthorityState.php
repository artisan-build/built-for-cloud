<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

final readonly class ManagedTransitionAuthorityState
{
    public function __construct(
        public ?string $transitionRequestId,
        public ?string $transitionId,
        public ?ManagedTransitionDirection $direction,
        public ?string $status,
        public int $rosterVersion,
        public ?string $rosterCutoffAt,
        public ?int $rosterTotal,
        public int $authorityGeneration,
        public ?string $localCommitReceipt,
        public ?string $acknowledgedAt,
    ) {}
}
