<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

final readonly class ManagedTransitionRosterPage
{
    /** @param list<ManagedTransitionRosterMember> $members */
    public function __construct(
        public array $members,
        public ?string $nextCursor,
        public int $pageTotal,
    ) {}
}
