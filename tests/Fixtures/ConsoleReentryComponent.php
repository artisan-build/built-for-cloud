<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use Livewire\Component;

final class ConsoleReentryComponent extends Component
{
    public function render(): string
    {
        return '<div>Console re-entry transport</div>';
    }
}
