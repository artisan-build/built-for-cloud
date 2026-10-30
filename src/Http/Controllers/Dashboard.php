<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\LandingManifest;
use ArtisanBuild\BuiltForCloud\View\AgentPrompts;
use Illuminate\Contracts\View\View;
use Illuminate\Support\Facades\App;

/**
 * The default dashboard every signed-in person lands on, for an app with no
 * screens of its own: prompts to copy into an agent that put questions to the
 * app through the Scalpels MCP. An app replaces it by naming its own invokable
 * controller or full-page Livewire component in BUILT_FOR_CLOUD_DASHBOARD.
 */
final readonly class Dashboard
{
    /** Render the default dashboard with the app's prompts, or general ones when it declares none. */
    public function __invoke(AgentPrompts $prompts): View
    {
        return view('bfc::dashboard', [
            'name' => App::make(LandingManifest::class)->name,
            'prompts' => $prompts->all(),
        ]);
    }
}
