<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

final class PreventBearerUrlPersistence
{
    /** @param Closure(Request): Response $next */
    public function handle(Request $request, Closure $next): Response
    {
        try {
            return $next($request);
        } finally {
            if ($request->hasSession()) {
                $request->session()->forget(['_previous.url', '_previous.route']);
                $request->session()->save();
            }
        }
    }
}
