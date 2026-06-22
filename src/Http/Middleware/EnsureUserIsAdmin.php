<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Middleware;

use Closure;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

final class EnsureUserIsAdmin
{
    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $user = Auth::user();

        if (! $user instanceof Model || ! (bool) $user->getAttribute('is_admin')) {
            abort(403);
        }

        return $next($request);
    }
}
