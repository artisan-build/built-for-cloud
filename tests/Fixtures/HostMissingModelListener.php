<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Queue\SerializesModels;

/**
 * A HOST queued listener (no package marker) carrying a model, so unserialising its
 * command restores that model. Used to prove that a model deleted after dispatch is
 * still handled by the framework rather than surfacing from the package's listener.
 */
final class HostMissingModelListener implements ShouldQueue
{
    use SerializesModels;

    public bool $deleteWhenMissingModels = true;

    public function __construct(public ?User $subject = null) {}

    public function handle(RogueListenerEvent $event): void {}
}
