<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use Illuminate\Support\Facades\Config as UiConfig;
use RuntimeException;

final class UiConfigFacadeEnforcementPath
{
    public function enforce(): void
    {
        if (! UiConfig::get('built-for-cloud.ui.rogue_facade_gate')) {
            throw new RuntimeException('The facade-backed UI gate denied access.');
        }
    }
}
