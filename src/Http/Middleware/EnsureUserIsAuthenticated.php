<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Middleware;

use ArtisanBuild\BuiltForCloud\OffboardedSubject;
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
            // Full account containment (PRD 1.15, SEC-V3-04): a session
            // that survived offboarding — a store the offboard verb could
            // not enumerate — dies HERE, on its first appearance: the
            // deactivated user is rejected and the surviving session is
            // invalidated, which is the stated compensation for session
            // drivers outside the offboard transaction's reach.
            $user = Auth::user();

            if ($user !== null && OffboardedSubject::userIsOffboarded((string) $user->getAuthIdentifier())) {
                if ($request->hasSession()) {
                    $request->session()->invalidate();
                }

                abort(403);
            }

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
