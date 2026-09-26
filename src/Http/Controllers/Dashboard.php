<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use Illuminate\Contracts\View\View;

/**
 * The default dashboard every signed-in person lands on. An app replaces it by
 * naming its own invokable controller or full-page Livewire component in
 * BUILT_FOR_CLOUD_DASHBOARD.
 */
final readonly class Dashboard
{
    /** Render the default dashboard, which points the way to settings. */
    public function __invoke(): View
    {
        return view('bfc::dashboard');
    }
}
