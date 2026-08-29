<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Middleware;

use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\Auth\CredentialGuard;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use Closure;
use Illuminate\Auth\AuthManager;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * Requires the authenticated credential to hold an explicit ability. FAILS
 * CLOSED: a credential with null or empty abilities is denied everything,
 * and a route registering this middleware without an ability string is a
 * configuration error, not an open door.
 *
 * Usage: `->middleware('bfc.ability:credential:read')`.
 *
 * This is the per-tool MCP enforcement primitive (PRD 1.10 / SEC-8): a
 * consuming app wires one instance of this middleware, with the tool's
 * required ability from the {@see OperatorAbility} vocabulary, in front of
 * EACH MCP tool route — `bfc.ability:mcp:read` on read tools,
 * `bfc.ability:mcp:admin` on destructive administration tools. The match
 * is EXACT: no ability implies another here (`credential:admin` included),
 * an ingest-scoped or MCP-read credential is 403 on a destructive tool,
 * and anything the `bfc` guard refuses — a legacy `api_tokens` secret, a
 * `FALLBACK_TOKEN` (the guard has no code path to it), an expired or
 * revoked row — is 401 before abilities are even consulted.
 *
 * A request arriving when the configured guard NAME has no guard at all
 * is a 401 too, deliberately: an app that never registered the `bfc`
 * guard must get a bounded refusal on a package route mounted with this
 * middleware, not a 500 out of the AuthManager.
 *
 * A denial of an AUTHENTICATED credential is audited as a `denied_action`
 * event (ids only), best-effort — the deny must stand even while the audit
 * store is down. Anonymous 401s are deliberately NOT audited here: this
 * middleware guards app-chosen (often public-facing MCP) routes, where
 * auditing unauthenticated noise would hand strangers a database-write
 * amplifier. The operator gate ({@see EnsureCredentialAdmin}) audits its
 * own auth failures — that surface is what GATE-3.7 names.
 */
final class EnsureCredentialAbility
{
    public function __construct(
        private readonly AuthManager $auth,
        private readonly CredentialDeclaration $declaration,
    ) {}

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next, ?string $ability = null): Response
    {
        if ($ability === null || $ability === '') {
            throw new InvalidArgumentException(
                'The bfc.ability middleware requires an explicit ability string.',
            );
        }

        $guardName = (string) config('built-for-cloud.credentials.guard', 'bfc');

        // No guard configured under that name at all. This is an
        // operator misconfiguration rather than an attack, but it is
        // still a request that cannot be authenticated, so it fails
        // CLOSED with the same 401 an unknown credential gets — the
        // structural check {@see EnsureUserIsAuthenticated} already
        // makes for the session gate. Resolving anyway would make the
        // AuthManager throw, turning every request to a package route
        // mounted with this middleware into a 500 on an app that never
        // added the `bfc` guard.
        //
        // The cost is stated rather than hidden: an operator who forgot
        // the guard sees the same 401 as a bad token, and has to look at
        // `auth.guards` to tell them apart.
        if (! is_array(config('auth.guards.'.$guardName))) {
            abort(401);
        }

        $guard = $this->auth->guard($guardName);

        if (! $guard instanceof CredentialGuard) {
            throw new InvalidArgumentException(
                "The [{$guardName}] guard is not a built-for-cloud credential guard.",
            );
        }

        if ($guard->guest()) {
            abort(401);
        }

        $credential = $guard->credential();

        if ($credential === null || ! $credential->hasAbility($ability)) {
            $this->auditDenial($request, $credential, $ability);

            abort(403);
        }

        if (! $this->declaration->authorize($credential, $ability, $request)) {
            $this->auditDenial($request, $credential, $ability);

            abort(403);
        }

        // Which credential this gate accepted, for downstream
        // attribution — the same attribute name and meaning
        // {@see EnsureCredentialAdmin} sets on its unified-store branch,
        // so a controller reads the actor the GATE authorized rather
        // than resolving the guard a second time.
        $request->attributes->set('bfc.actor_credential_id', $credential->id);

        return $next($request);
    }

    /**
     * The denied-action audit for an authenticated credential that lacks
     * the tool's ability (GATE-3.7 observability). Ids only, best-effort.
     */
    private function auditDenial(Request $request, ?Credential $credential, string $ability): void
    {
        try {
            DB::transaction(function () use ($request, $credential, $ability): void {
                app(LifecycleEventRecorder::class)->record(
                    event: LifecycleEventType::DeniedAction,
                    credentialId: $credential?->id,
                    actor: $credential === null ? null : AuditActor::operatorIntegration($credential->id),
                    note: 'denied: credential lacks '.$ability.' ('.$request->method().' /'.$request->path().')',
                );
            });
        } catch (Throwable) {
            // Losing the audit row must not convert a deny into a 500.
        }
    }
}
