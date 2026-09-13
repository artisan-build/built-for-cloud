<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

final class RogueLegacyEvent
{
    public RogueLegacyValue $legacy;

    public function __construct(public string $userId, public string $connection = 'sync')
    {
        $this->legacy = new RogueLegacyValue;
    }
}
