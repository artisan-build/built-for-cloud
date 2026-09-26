<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures\Dashboards;

use Livewire\Component;

/** An app's own full-page Livewire dashboard, standing in for one named by BUILT_FOR_CLOUD_DASHBOARD. */
final class AppDashboardComponent extends Component
{
    /** Render a marker the tests look for inside the layout. */
    public function render(): string
    {
        return '<div data-testid="app-dashboard-component">App dashboard</div>';
    }
}
