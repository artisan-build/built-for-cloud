<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use Illuminate\Contracts\Queue\ShouldQueue;

class InheritedQueuedParent implements ShouldQueue
{
    public function handle(): void {}
}
