<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Middleware;

use ArtisanBuild\BuiltForCloud\Console\ActingPrincipalResolver;
use ArtisanBuild\BuiltForCloud\Console\ConsoleGuardConfiguration;
use ArtisanBuild\BuiltForCloud\Console\ConsoleRole;
use ArtisanBuild\BuiltForCloud\OffboardedSubject;
use Closure;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * `bfc.admin` — an ADMINISTRATIVE standing gate, and one that CONSUMES
 * D14's resolved acting principal rather than refusing it.
 *
 * A delegated operator carrying `role=admin` is exactly what the Console
 * exists to deliver (PRD D8: the vendor's own roles collapse to
 * `admin`/`member` at mint time and the app maps those two onto its own
 * policies), so an admin gate that demanded an `is_admin` column would
 * refuse the one principal the whole feature is for. This gate therefore
 * asks {@see ActingPrincipalResolver} who is acting and answers per
 * principal TYPE.
 *
 * ADMISSION IS EXACT. A delegated actor passes only when it is the
 * ACTING principal — that is, only on a route whose own guard is the
 * console guard (`auth:bfc-console`), so that
 * everything behind this gate — `$request->user()`, `Auth::user()`,
 * `Gate`, every policy — resolves to the SAME object this gate
 * authorized. Admitting a delegated admin on a route that then acts as
 * a co-resident local user is the confused deputy (FLEET-C-02), and it
 * is the one outcome this gate must never produce. So:
 *
 * - a DELEGATED actor that is the acting principal passes if and only
 *   if THIS SESSION's own handoff carried `admin` — the role is
 *   session-bound, so a later handoff for the same human cannot promote
 *   a live `member` session;
 * - a request-scoped delegated assertion is refused even when it carries
 *   `admin`: it has no browser-session identity, and this gate admits the
 *   Console guard's principal specifically;
 * - a delegated session that is present but is NOT the acting principal
 *   (the route is guarded by the app's own guard) is a 403, and
 *   deliberately not a fall-through to the local user's `is_admin`:
 *   D14 says the delegated principal governs, so a local admin session
 *   must not lend its standing to a delegated operator the route never
 *   scoped itself to;
 * - a REFUSED delegated session is terminal here too — 403, never
 *   re-resolved against the local user;
 * - a LOCAL user passes on the app's own `is_admin` attribute, exactly
 *   as before, and is still checked for offboarding containment;
 * - anything else is 403.
 *
 * OFFBOARDING is a LOCAL containment registry keyed on host-app user
 * ids, so it is checked for the local branch only; a delegated actor's
 * containment is its own `deactivated_at`, enforced at the guard/provider
 * or assertion middleware before this gate ever runs.
 */
final class EnsureUserIsAdmin
{
    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $acting = app(ActingPrincipalResolver::class)->resolve();

        if ($acting->delegated && $acting->guard === ConsoleGuardConfiguration::GUARD) {
            if ($acting->role !== ConsoleRole::Admin) {
                abort(403);
            }

            return $next($request);
        }

        if ($acting->delegatedSessionPresent()) {
            abort(403);
        }

        $user = $acting->principal;

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
