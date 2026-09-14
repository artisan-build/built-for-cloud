<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\InventoryFixtures;

final class PublishedConfigRogueRead
{
    /** @return array{mixed, mixed, mixed} */
    public function read(): array
    {
        return [
            config('built-for-cloud.manifest'),
            config('built-for-cloud.ui.rogue_surface'),
            config('built-for-cloud.credentials.app_purposes'),
        ];
    }
}
