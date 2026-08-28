<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;

/**
 * A deliberately leaky job: it carries a raw secret marker in its payload so
 * the harness's queue channel has something to catch. Exactly the shape D7
 * forbids in production code.
 */
final class MarkerCarryingJob implements ShouldQueue
{
    use Dispatchable;
    use Queueable;

    public function __construct(public string $secret) {}

    public function handle(): void
    {
        // The leak is the payload, not the work.
    }
}
