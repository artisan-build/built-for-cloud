<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Middleware;

use ArtisanBuild\BuiltForCloud\Console\ActingPrincipalResolver;
use ArtisanBuild\BuiltForCloud\OffboardedSubject;
use ArtisanBuild\BuiltForCloud\PersonalCredentialSurface;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Symfony\Component\HttpFoundation\Response;

/**
 * `bfc.auth` — the gate for a surface that acts as THE AUTHENTICATED
 * LOCAL HUMAN, and only one.
 *
 * IT CONSUMES THE RESOLVED PRINCIPAL. It does not call `Auth::check()`
 * or `Auth::user()` itself. That is not a style preference: on
 * `/bfc/me/credentials` the rate limiter has already called
 * `$request->user()` before this middleware runs, so the local session
 * guard is holding that user in memory, and a gate that asked the facade
 * would be reading a cache rather than a decision.
 * {@see ActingPrincipalResolver} is the decision, and reading it is also
 * what makes D7's absolute cap bite on this route — the resolver reads
 * the console guard, and the console guard is what destroys a capped
 * session.
 *
 * THREE OUTCOMES:
 *
 * - A DELEGATED SESSION IS PRESENT on the request — live, and whichever
 *   guard the route itself names: REFUSED with a 403. A delegated actor
 *   has no personal identity in this application, so a surface that can
 *   only act as a local user says no rather than quietly acting as
 *   somebody else's identity. On the personal-credentials surface that
 *   fall-through would mean minting or revoking a local human's
 *   credentials while a delegated operator is the one at the keyboard
 *   (FLEET-C-02). The check is deliberately BROADER than "the delegated
 *   actor is the acting principal": refusing costs only convenience,
 *   while acting as the wrong human does not, so this direction is
 *   allowed to be blunt. A 403 rather than a 401 because the caller IS
 *   authenticated — as the wrong kind of principal for this surface —
 *   and logging in again would change nothing.
 * - A delegated session was REFUSED (capped, unreadable, contained):
 *   TERMINAL. The request is unauthenticated and does not fall back to
 *   the local user, whose session the guard has just invalidated
 *   anyway.
 * - Otherwise the local user, unchanged, offboarding containment check
 *   and all.
 *
 * Gates that CONSUME the resolved principal instead of refusing it are a
 * different case and are handled differently: see
 * {@see EnsureUserIsAdmin}, where a delegated `admin` legitimately
 * passes — and only when the route's own guard is the console guard, so
 * admission is exact where refusal may be broad. The surface itself
 * carries the same refusal ({@see PersonalCredentialSurface}), because
 * it is public API an app's own screen may call with no middleware in
 * front of it.
 */
final class EnsureUserIsAuthenticated
{
    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $acting = app(ActingPrincipalResolver::class)->resolve();

        if ($acting->wasRefused()) {
            return $this->unauthenticated($request);
        }

        if ($acting->delegatedSessionPresent()) {
            abort(403, 'A delegated console actor has no personal identity in this application, so this surface refuses it rather than acting as the local session user.');
        }

        $user = $acting->principal;

        if ($user === null) {
            return $this->unauthenticated($request);
        }

        // Full account containment (PRD 1.15, SEC-V3-04): a session
        // that survived offboarding — a store the offboard verb could
        // not enumerate — dies HERE, on its first appearance: the
        // deactivated user is rejected and the surviving session is
        // invalidated, which is the stated compensation for session
        // drivers outside the offboard transaction's reach.
        if (OffboardedSubject::userIsOffboarded((string) $user->getAuthIdentifier())) {
            if ($request->hasSession()) {
                $request->session()->invalidate();
            }

            abort(403);
        }

        return $next($request);
    }

    /**
     * The one unauthenticated answer, shared by "nobody is logged in"
     * and "the delegated session was refused" — from the caller's side
     * they are the same state, and a refused console session must not be
     * distinguishable from an absent one by anything but the
     * `bfc.console` gate's own structured 401.
     */
    private function unauthenticated(Request $request): Response
    {
        if ($request->expectsJson()) {
            abort(401);
        }

        if (Route::has('login')) {
            return redirect()->route('login');
        }

        abort(401);
    }
}
