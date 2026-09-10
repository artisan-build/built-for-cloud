<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\StandaloneRouteOwnership;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Routing\Route;
use RuntimeException;

abstract class OperatorRouteController extends Controller
{
    /**
     * @param  string  $method
     * @param  array<string, mixed>  $parameters
     */
    public function callAction($method, $parameters): mixed
    {
        $action = $method === '__invoke' ? static::class : static::class.'@'.$method;
        $gate = StandaloneRouteOwnership::operatorGateForAction($action);
        $request = app(Request::class);
        $route = $request->route();

        if (! $route instanceof Route) {
            throw new RuntimeException("The operator controller action [{$action}] has no resolved route.");
        }

        if ($gate !== null) {
            StandaloneRouteOwnership::assertOperatorGateExecuted($request, $route, $gate);
        }

        return parent::callAction($method, $parameters);
    }
}
