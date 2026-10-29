<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures\Layouts;

use Illuminate\Contracts\View\View as ViewContract;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\View;
use Livewire\Attributes\Title;
use Livewire\Component;

/** A full-page Livewire component with no layout of its own, so it lands in whatever layout is configured. */
#[Title('Full page')]
final class FullPageLivewireComponent extends Component
{
    public string $sidebarSentinel = '';

    public function mount(): void
    {
        $this->sidebarSentinel = Config::string('layout-test.sidebar-sentinel', 'Livewire navigation sentinel');
    }

    /** Render a marker the tests look for inside the layout's main element. */
    public function render(): ViewContract
    {
        return View::file(dirname(__DIR__).'/views/full-page-livewire.blade.php');
    }
}
