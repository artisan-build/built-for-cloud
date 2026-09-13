<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Queue\SerializesModels;

/**
 * A `SerializesModels` event — the `make:event` stub's own default — carrying a model.
 * Queueing a listener on it puts a ModelIdentifier in the WRAPPER's payload, which is
 * the deleted-model scenario I twice claimed could not exist: the listener instance is
 * indeed never serialised, but the EVENT it is called with is.
 */
final class RogueModelEvent
{
    use SerializesModels;

    public function __construct(public User $user) {}
}
