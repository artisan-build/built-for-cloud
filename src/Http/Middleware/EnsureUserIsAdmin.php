<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Middleware;

use ArtisanBuild\BuiltForCloud\OffboardedSubject;
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

        // Full account containment (PRD 1.15, SEC-V3-04 / rework Fix 3):
        // an offboarded user is rejected on EVERY package-guarded route —
        // this middleware is registered without bfc.auth on some routes,
        // so it carries the check itself, whatever session store kept the
        // session alive. The surviving session dies on this first
        // appearance.
        if (OffboardedSubject::userIsOffboarded((string) $user->getAuthIdentifier())) {
            if ($request->hasSession()) {
                $request->session()->invalidate();
            }

            abort(403);
        }

        return $next($request);
    }
}
