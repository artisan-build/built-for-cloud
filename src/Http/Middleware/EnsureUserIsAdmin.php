<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Middleware;

use ArtisanBuild\BuiltForCloud\Console\ActingPrincipalResolver;
use ArtisanBuild\BuiltForCloud\ManagedAccountAccess;
use ArtisanBuild\BuiltForCloud\OffboardedSubject;
use ArtisanBuild\BuiltForCloud\RolePolicy;
use ArtisanBuild\BuiltForCloud\StandaloneAccess;
use ArtisanBuild\BuiltForCloud\User;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

/**
 * `bfc.admin` — an ADMINISTRATIVE standing gate, and one that CONSUMES
 * the resolved acting principal rather than refusing it.
 *
 * It asks {@see ActingPrincipalResolver} who is acting and answers per
 * principal TYPE:
 *
 * - a request-scoped delegated assertion is refused even when it carries
 *   `admin`: it has no browser-session identity, and this gate admits
 *   the local administrator specifically;
 * - a LOCAL package user passes when its role can manage Members, and is
 *   still checked for offboarding containment;
 * - anything else is 403.
 *
 * OFFBOARDING is a LOCAL containment registry keyed on canonical package user
 * ids, so it is checked for the local branch only; a delegated actor's
 * containment is its own `deactivated_at`, enforced at the assertion
 * middleware before this gate ever runs.
 */
final class EnsureUserIsAdmin
{
    public function __construct(private readonly ManagedAccountAccess $managedAccess) {}

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $acting = app(ActingPrincipalResolver::class)->resolve();

        if ($acting->delegatedSessionPresent()) {
            abort(403);
        }

        $user = $acting->principal;

        if (! $user instanceof User) {
            abort(403);
        }

        if ($user->status !== 'active') {
            if ($request->hasSession()) {
                $request->session()->invalidate();
            }

            abort(403);
        }

        if (! RolePolicy::canManageMembers($user->role)) {
            abort(403);
        }

        if (! StandaloneAccess::sessionVersionIsCurrent($request, $user)) {
            StandaloneAccess::endCurrentSession(
                $request,
                is_string($acting->guard) ? Auth::guard($acting->guard) : null,
            );

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

        if (! $this->managedAccess->allows($user)) {
            StandaloneAccess::endCurrentSession(
                $request,
                is_string($acting->guard) ? Auth::guard($acting->guard) : null,
            );

            abort(403);
        }

        return $next($request);
    }
}
