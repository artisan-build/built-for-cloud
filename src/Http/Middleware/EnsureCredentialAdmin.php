<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Middleware;

use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\Auth\CredentialResolver;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialUsageRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\TokenRegistry;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * The gate on the unified store's own verb routes (`/bfc/credentials`):
 * accepts EITHER a legacy admin `api_tokens` row (exactly what
 * {@see EnsureAdminToken} accepts, unchanged) OR a unified-store `bearer`
 * credential with the `operator` subject holding the route's REQUIRED
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
 * Which store authenticated is visible downstream: the legacy branch
 * stashes `bfc.actor_token_id` (audited as an `admin_token` actor), the
 * unified branch `bfc.actor_credential_id` (audited as an
 * `operator_integration` actor).
 *
 * Observability (GATE-3.7): every token-auth FAILURE (401) and every
 * DENIED action (403) on this gate appends a `denied_action` event to the
 * PR4 audit stream — ids only, never presented secrets. The denial itself
 * never depends on the audit write: containment must hold even while the
 * audit store is down, so the append is best-effort here (denials carry no
 * state transition to keep it transactional with).
 *
 * The FALLBACK token is rejected here EXPLICITLY, with a distinguishable
 * 403, and BEFORE either granting branch — the invariant is absolute even
 * under a config whose fallback bytes collide with a real credential's
 * secret. The env pseudo-credential is deprecated (PRD 1.20) and never
 * operates this surface; silently treating it as unknown would send its
 * holder chasing a typo instead of the real fix.
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
        private readonly TokenRegistry $tokens,
        private readonly CredentialResolver $credentials,
        private readonly CredentialUsageRecorder $usage,
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
            $this->tokens->observeUnauthenticatedClientIdentity($request);

            $this->auditDenial($request, 'token_auth_failure: no credential presented', null);

            abort(401);
        }

        // The deprecated fallback pseudo-credential is rejected FIRST,
        // before either granting branch, so "the fallback never operates
        // this surface" is absolute: even a config whose fallback bytes
        // collide with a real credential's secret rejects here — nothing
        // resolves, nothing stamps usage. Distinguishable, so its holder
        // chases the real fix rather than a typo.
        if ($this->isFallback($bearer)) {
            $this->auditDenial($request, 'denied: fallback token on an operator surface', null);

            abort(403, 'Fallback tokens never operate the credential verbs. Mint an operator credential with bfc:install:operator-credential instead.');
        }

        // Branch 1 — the legacy admin token, byte-for-byte EnsureAdminToken
        // semantics (client-identity attribution included). An admin
        // `api_tokens` row is admin-equivalent on every operator verb —
        // exactly what the public contract's "admin token" auth promises.
        $token = $this->tokens->resolveModel($bearer);

        if ($token !== null) {
            $this->tokens->recordClientIdentityFromRequest($request, $token);

            if ($token->hasScope(Scope::Admin)) {
                $request->attributes->set('bfc.actor_token_id', (string) $token->getKey());

                return $next($request);
            }

            $this->auditDenial($request, 'denied: token without admin scope', AuditActor::adminToken((string) $token->getKey()));

            abort(403);
        }

        // Branch 2 — a unified-store operator credential. Presenting it is
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

            // Least privilege per verb family: the route's required
            // ability, or the explicit admin-equivalent break-glass
            // (`credential:admin` — the documented mapping in
            // {@see OperatorAbility}). Nothing else satisfies; a null or
            // empty ability list satisfies nothing.
            if ($credential->subject_type === SubjectType::Operator
                && ($credential->hasAbility($required) || $credential->hasAbility(self::ABILITY))) {
                $request->attributes->set('bfc.actor_credential_id', $credential->id);

                return $next($request);
            }

            // A working credential without this verb's authority: it
            // authenticated, so this is a scope failure, not an unknown.
            $this->auditDenial($request, 'denied: credential lacks '.$required, AuditActor::operatorIntegration($credential->id));

            abort(403);
        }

        $this->tokens->observeUnauthenticatedClientIdentity($request);

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

    /**
     * The fallback bytes themselves, compared directly — never through a
     * resolver that could touch rows or record usage.
     */
    private function isFallback(string $bearer): bool
    {
        $fallback = config('built-for-cloud.fallback_token');

        return is_string($fallback)
            && $fallback !== ''
            && hash_equals(hash('sha256', $fallback), hash('sha256', $bearer));
    }
}
