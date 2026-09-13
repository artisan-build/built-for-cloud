<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\AuditActor;

final class RogueInheritedQueuedJob extends InheritedQueuedParent
{
    public function handle(): void
    {
        AuditActor::boundUser('inherited-queue-human');
    }
}
