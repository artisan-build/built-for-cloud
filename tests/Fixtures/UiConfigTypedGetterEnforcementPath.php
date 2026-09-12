<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use Illuminate\Support\Facades\Config;
use RuntimeException;

final class UiConfigTypedGetterEnforcementPath
{
    public function enforce(): void
    {
        if (! Config::boolean('built-for-cloud.ui.rogue_typed_gate')) {
            throw new RuntimeException('The typed UI gate denied access.');
        }
    }
}
