<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\InventoryFixtures;

use Illuminate\Routing\Router;
use RuntimeException;

final class UiConditionedOwnershipAssertion
{
    public static function assertOwned(Router $router): void
    {
        if (config('built-for-cloud.ui.landing_page') !== true) {
            throw new RuntimeException('UI hid the ownership assertion.');
        }
    }
}
