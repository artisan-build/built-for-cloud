<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures\Layouts;

use Livewire\Attributes\Title;
use Livewire\Component;

/** A full-page Livewire component with no layout of its own, so it lands in whatever layout is configured. */
#[Title('Full page')]
final class FullPageLivewireComponent extends Component
{
    /** Render a marker the tests look for inside the layout's main element. */
    public function render(): string
    {
        return '<div data-testid="full-page-livewire">Full page body</div>';
    }
}
