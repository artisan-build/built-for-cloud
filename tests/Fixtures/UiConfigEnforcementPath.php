<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use RuntimeException;

final class UiConfigEnforcementPath
{
    public function enforce(): void
    {
        if (! config('built-for-cloud.ui.rogue_gate', false)) {
            throw new RuntimeException('The UI flag refused an enforcement path.');
        }
    }
}
