<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Middleware;

use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\Auth\CredentialResolver;
use ArtisanBuild\BuiltForCloud\ClientIdentityRecorder;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialUsageRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\StandaloneRouteOwnership;
use ArtisanBuild\BuiltForCloud\SubjectType;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * The gate on the unified store's own verb routes (`/bfc/credentials`):
 * accepts a unified-store `bearer` credential with the `operator` subject
 * holding the route's REQUIRED
 * ABILITY (GATE-3.7's per-verb-family authority): each route names its
 * verb-family ability as the middleware parameter
 * (`bfc.credential.admin:credential:read`), and the admin-equivalent
 * {@see self::ABILITY} — what the installer mints (PRD 1.20) — satisfies
 * ANY ability a route names. Note the shape of that grant precisely: it
 * is unconditional, not a lookup. This gate never reads
 * {@see OperatorAbility::adminEquivalent}, which is a declared inventory
 * of the abilities these routes ask for today rather than a set the
 * break-glass is confined to. Without the operator branch the install-time
 * credential would be 401 on the one surface it exists to manage; without
 * the per-verb parameter a stolen read-only credential would be
 * fleet-admin (SEC-V3-06).
 *
 * The accepted row is visible downstream as `bfc.actor_credential_id` and
 * audited as an `operator_integration` actor.
 *
 * Observability (GATE-3.7): every token-auth FAILURE (401) and every
 * DENIED action (403) on this gate appends a `denied_action` event to the
 * PR4 audit stream — ids only, never presented secrets. The denial itself
 * never depends on the audit write: containment must hold even while the
 * audit store is down, so the append is best-effort here (denials carry no
 * state transition to keep it transactional with).
 *
 */
final class EnsureCredentialAdmin
{
    /**
     * The admin-equivalent ability a unified-store operator credential
     * may hold to operate EVERY credential verb over HTTP — the explicit
     * break-glass name in the {@see OperatorAbility} vocabulary (its
     * documented expansion is {@see OperatorAbility::adminEquivalent}).
     * The installer mints its operator credential with exactly this.
     *
     * `metadata:read` ({@see OperatorAbility::MetadataRead}) is now
     * enforced, and NOT here: the Console's dashboard read is mounted
     * behind {@see EnsureDashboardCredential} — its own gate, and the
     * only middleware on that route — precisely because THIS gate would
     * grant the ability to a break-glass credential, which Console PRD
     * D16 forbids.
     */
    public const string ABILITY = 'credential:admin';

    public function __construct(
        private readonly CredentialResolver $credentials,
        private readonly CredentialUsageRecorder $usage,
        private readonly ClientIdentityRecorder $clientIdentities,
    ) {}

    /**
     * @param  Closure(Request): Response  $next
     * @param  string|null  $ability  the route's required verb-family
     *                                ability (GATE-3.7); null keeps the
     *                                pre-1.10 admin-equivalent requirement
     */
    public function handle(Request $request, Closure $next, ?string $ability = null): Response
    {
        $required = $ability ?? self::ABILITY;

        $bearer = $request->bearerToken();

        if ($bearer === null || $bearer === '') {
            $this->clientIdentities->observeUnauthenticatedClientIdentity($request);

            $this->auditDenial($request, 'token_auth_failure: no credential presented', null);

            abort(401);
        }

        // Presenting a unified-store operator credential is
        // a use: the gated recorder both stamps it and re-asserts the row
        // still authenticates (SEC-2). Full account containment (PRD
        // 1.15) needs no check here: an offboarded principal never
        // resolves — {@see CredentialResolver}, the containment choke
        // point — so it lands in the final token_auth_failure branch
        // below, use unrecorded, indistinguishable from an unknown
        // secret.
        $credential = $this->credentials->resolve(CredentialKind::Bearer, $bearer);

        if ($credential !== null) {
            if (! $this->usage->recordUsage($credential)) {
                $this->auditDenial($request, 'token_auth_failure: credential died before use', null);

                abort(401);
            }

            $this->clientIdentities->recordClientIdentityFromRequest($request, $credential);

            // Least privilege per verb family: the route's required
            // ability, or the explicit admin-equivalent break-glass
            // (`credential:admin` — the documented mapping in
            // {@see OperatorAbility}). Nothing else satisfies; a null or
            // empty ability list satisfies nothing.
            if ($credential->subject_type === SubjectType::Operator
                && ($credential->hasAbility($required) || $credential->hasAbility(self::ABILITY))) {
                $request->attributes->set('bfc.actor_credential_id', $credential->id);
                StandaloneRouteOwnership::markOperatorGateExecuted($request, self::class.':'.$required);

                return $next($request);
            }

            // A working credential without this verb's authority: it
            // authenticated, so this is a scope failure, not an unknown.
            $this->auditDenial($request, 'denied: credential lacks '.$required, AuditActor::operatorIntegration($credential->id));

            abort(403);
        }

        $this->clientIdentities->observeUnauthenticatedClientIdentity($request);

        $this->auditDenial($request, 'token_auth_failure: unknown credential', null);

        abort(401);
    }

    /**
     * GATE-3.7's denial/auth-failure audit: a `denied_action` event, ids
     * only. Best-effort by design — the DENY must stand even while the
     * audit store is unreachable, and a denial has no state transition
     * whose transaction the event could ride.
     */
    private function auditDenial(Request $request, string $note, ?AuditActor $actor): void
    {
        try {
            DB::transaction(function () use ($request, $note, $actor): void {
                app(LifecycleEventRecorder::class)->record(
                    event: LifecycleEventType::DeniedAction,
                    actor: $actor,
                    note: $note.' ('.$request->method().' /'.$request->path().')',
                );
            });
        } catch (Throwable) {
            // The denial response is the containment; losing its audit row
            // must not convert a deny into a 500.
        }
    }

}
