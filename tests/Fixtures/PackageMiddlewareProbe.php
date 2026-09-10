<?php

declare(strict_types=1);

// The production namespace exercises discovery; this test-only path is outside its PSR-4 autoload mapping.
namespace ArtisanBuild\BuiltForCloud\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

final class PackageMiddlewareProbe
{
    /** @param  Closure(Request): Response  $next */
    public function handle(Request $request, Closure $next): Response
    {
        return $next($request);
    }
}
