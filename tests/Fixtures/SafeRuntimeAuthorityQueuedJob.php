<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Contracts\SystemAuthorityQueueEntry;
use Illuminate\Contracts\Queue\ShouldQueue;

final class SafeRuntimeAuthorityQueuedJob implements ShouldQueue, SystemAuthorityQueueEntry
{
    public function handle(): void
    {
        config()->set('runtime-authority.safe-package-job-finished', true);
    }
}
