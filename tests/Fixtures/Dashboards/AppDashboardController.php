<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures\Dashboards;

/** An app's own dashboard controller, standing in for one named by BUILT_FOR_CLOUD_DASHBOARD. */
final class AppDashboardController
{
    /** Answer with a marker the tests look for. */
    public function __invoke(): string
    {
        return 'app-dashboard-controller';
    }
}
