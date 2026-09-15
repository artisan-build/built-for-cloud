<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\InventoryFixtures;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

final class UiConditionedHumanGate
{
    /** @param Closure(Request): Response $next */
    public function handle(Request $request, Closure $next): Response
    {
        if (config('built-for-cloud.ui.member_management') !== true) {
            abort(403);
        }

        return $next($request);
    }
}
