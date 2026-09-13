<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Auth;

/**
 * A HOST job carrying no package marker, whose displayName is COPIED from a package
 * job. Identity must come from the payload's `commandName`, so this must stay
 * unframed and must authenticate freely. Reverting identity to `resolveName()` makes
 * the copied name win and reds the control — which the previous version of this
 * fixture could not do, because it declared no display name at all.
 */
final class HostCopycatQueuedJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public function __construct(public string $userId) {}

    public function displayName(): string
    {
        return RogueMiddlewareLoginJob::class;
    }

    public function handle(): void
    {
        Auth::guard('web')->loginUsingId($this->userId);
    }
}
