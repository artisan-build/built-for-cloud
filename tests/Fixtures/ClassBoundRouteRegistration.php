<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use Illuminate\Routing\Route;

final class ClassBoundRouteRegistration
{
    public function protect(Route $route): void
    {
        $gate = ClassBoundRouteOwnership::operatorGateForAction($route->getActionName());

        $route->middleware($gate);
    }
}
