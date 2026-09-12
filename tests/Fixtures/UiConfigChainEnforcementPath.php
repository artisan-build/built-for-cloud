<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use RuntimeException;

final class UiConfigChainEnforcementPath
{
    public function enforce(): void
    {
        if (! config()->get('built-for-cloud.ui.rogue_chain_gate')) {
            throw new RuntimeException('The chained UI gate denied access.');
        }
    }
}
