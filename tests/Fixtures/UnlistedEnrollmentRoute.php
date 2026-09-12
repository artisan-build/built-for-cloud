<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageOnboarding;
use Illuminate\Routing\Router;

final class UnlistedEnrollmentRoute
{
    public function mount(Router $router): void
    {
        $router->post('/bfc/unlisted-enrollment', [ManageOnboarding::class, 'exchange']);
    }
}
