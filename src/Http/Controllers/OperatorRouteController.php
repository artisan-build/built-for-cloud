<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\StandaloneRouteOwnership;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Routing\Route;

abstract class OperatorRouteController extends Controller
{
    /**
     * @param  array<string, mixed>  $parameters
     */
    public function callAction($method, $parameters): mixed
    {
        $request = app(Request::class);
        $route = $request->route();

        if ($route instanceof Route) {
            $gate = StandaloneRouteOwnership::operatorGateForAction($route->getActionName());

            if ($gate !== null) {
                StandaloneRouteOwnership::assertOperatorGateExecuted($request, $route, $gate);
            }
        }

        return parent::callAction($method, $parameters);
    }
}
