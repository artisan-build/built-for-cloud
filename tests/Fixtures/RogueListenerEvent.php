<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

final class RogueListenerEvent
{
    public function __construct(public string $userId, public string $connection = 'sync') {}
}
