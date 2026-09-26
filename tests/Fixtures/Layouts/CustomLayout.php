<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures\Layouts;

use Illuminate\Contracts\View\View as ViewContract;
use Illuminate\Support\Facades\View;
use Illuminate\View\Component;

/** A fork-owned layout that shares nothing with the package's, standing in for one named by BUILT_FOR_CLOUD_LAYOUT. */
final class CustomLayout extends Component
{
    public function __construct(public ?string $title = null) {}

    /** Render a shell with its own marker so tests can tell it apart from the package layout. */
    public function render(): ViewContract
    {
        return View::make('layout-fixtures::custom-layout');
    }
}
