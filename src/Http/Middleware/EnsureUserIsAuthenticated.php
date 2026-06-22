<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Symfony\Component\HttpFoundation\Response;

final class EnsureUserIsAuthenticated
{
    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        if (Auth::check()) {
            return $next($request);
        }

        if ($request->expectsJson()) {
            abort(401);
        }

        if (Route::has('login')) {
            return redirect()->route('login');
        }

        abort(401);
    }
}
