<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\AuditActor;
use Illuminate\Contracts\Queue\ShouldQueueAfterCommit;

final class RogueAfterCommitQueuedJob implements ShouldQueueAfterCommit
{
    public function handle(): void
    {
        AuditActor::boundUser('after-commit-human');
    }
}
