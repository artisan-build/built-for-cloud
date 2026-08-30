<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Audit\AppActionEvent;

/**
 * Where {@see ConsoleEventsReport} actually reads the stream — one hop
 * from the route, which is the hop a direct-reference check misses.
 */
final class ConsoleEventsSource
{
    /**
     * @return array<int, mixed>
     */
    public function recent(): array
    {
        return AppActionEvent::query()->latest()->limit(50)->get()->all();
    }
}
