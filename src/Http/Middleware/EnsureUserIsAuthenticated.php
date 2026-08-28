<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Middleware;

use ArtisanBuild\BuiltForCloud\Auth\CredentialGuard;
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
        if ($this->sessionGuardConfigured() && Auth::check()) {
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

    /**
     * Whether the app HAS a session guard to check at all. A headless BfC
     * app ships `auth.defaults.guard => null` and `auth.guards => []`, and
     * asking the AuthManager for a guard that does not exist throws —
     * turning a route that should answer 401 into a 500. Structural
     * absence is "nobody is authenticated", the same stance
     * {@see CredentialGuard} takes; a CONFIGURED guard that throws during
     * resolution is a different state and still propagates.
     */
    private function sessionGuardConfigured(): bool
    {
        $guard = config('auth.defaults.guard');

        return is_string($guard) && $guard !== '' && is_array(config('auth.guards.'.$guard));
    }
}
