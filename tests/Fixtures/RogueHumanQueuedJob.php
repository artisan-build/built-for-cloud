<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Contracts\Queue\ShouldQueue;

final class RogueHumanQueuedJob implements ShouldQueue
{
    public function handle(): void
    {
        $user = User::query()->first();
        AuditActor::boundUser((string) $user?->getKey());
    }
}
