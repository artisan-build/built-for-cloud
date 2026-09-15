<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Support;

/** A counter-backed fake proving whether the post-admission replay seam ran. */
final class ContractMajorLiveReplayStore
{
    public function has(string $key): bool
    {
        ContractMajorLiveState::increment('replay_store_reads');

        return false;
    }

    public function put(string $key): void
    {
        ContractMajorLiveState::increment('replay_store_writes');
    }
}
