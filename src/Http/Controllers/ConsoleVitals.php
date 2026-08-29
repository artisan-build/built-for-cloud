<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAbility;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureDashboardCredential;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\Vitals\CollectVitals;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

/**
 * `GET /bfc/console/vitals` — the ops-vitals surface the fleet dashboard
 * reads (Console PRD D9/D15/D16), classified `metadata`.
 *
 * ITS GATE IS TWO LAYERS, and both are D16 rather than style.
 *
 * `bfc.ability:metadata:read` ({@see EnsureCredentialAbility}) is the
 * outer one. D16 forbids "using the ownership/admin credential for any
 * dashboard read path", and the operator gate
 * ({@see EnsureCredentialAdmin}) cannot enforce that: it grants a
 * `credential:admin` credential whatever ability a route names,
 * unconditionally and without consulting any list, so a break-glass
 * credential would have passed a route mounted behind it. This gate
 * matches EXACTLY — no ability implies another, `credential:admin`
 * included — and it authenticates through the `bfc` guard, which
 * resolves the unified store only, so a legacy admin `api_tokens` secret
 * and a `FALLBACK_TOKEN` never authenticate here at all.
 *
 * {@see EnsureDashboardCredential} is the inner one, and it is what
 * makes the rule EXCLUSIVITY rather than membership: an operator
 * subject, and an abilities list exactly equal to `{metadata:read}`.
 * Without it a credential holding both `metadata:read` and
 * `credential:admin` reads the dashboard and mutates every operator
 * surface, which satisfies the ability check and violates D16's
 * "unable to touch content-classified or mutating surfaces" outright.
 *
 * The route is consequently reachable by one thing: a live
 * operator-subject unified-store credential whose abilities list is
 * exactly {@see OperatorAbility::MetadataRead} and nothing else.
 *
 * THE AUDIT IS TRANSACTIONAL, NOT BEST-EFFORT, and it runs BEFORE the
 * payload is assembled. **D16 refuses an unaudited read**: the ability
 * it defines is read-audited, so a vendor read this deployment cannot
 * record is one it must not serve. That makes the audit append the one
 * thing on this route that can produce a 500, deliberately. Running it
 * first fixes which way that failure leans — a recorded read that then
 * failed to serve, rather than a served read nobody recorded.
 *
 * No D9 exception is claimed for this, because D9 grants none. D9 says
 * an unreachable or stale app renders as an honest degraded row rather
 * than breaking the dashboard — and an app that answers 500 IS
 * unreachable from the dashboard's side, so it renders as exactly that
 * row. D9 is working in that case, not being suspended. What D9 does
 * govern here is the payload's own contents: an unreachable queue or a
 * refused declaration degrades the report instead of erroring it
 * ({@see CollectVitals}).
 *
 * The append does NOT drain the outbox (`drainAfterCommit: false`). A
 * drain is O(claimable rows) and may send mail; hanging one off a route
 * polled sixty times a minute per credential would make a dashboard poll
 * a database and mail amplifier. The outbox row is still written in the
 * same transaction and is delivered by the next drain.
 *
 * WHAT THE AUDIT ROW CONTAINS, stated precisely because "ids only" was
 * the wrong claim: no request or response body, no presented secret, and
 * no credential material. It does carry this instance's configured
 * `product` and cloud application name in the stream's standard
 * `provider` / `deployment` columns, which are operator-authored strings
 * — those columns are the SAME on every event in this instance-side
 * stream, and the stream is not a `metadata`-classified vendor surface.
 */
final class ConsoleVitals
{
    /**
     * The optional request header a caller uses to state which
     * `api_version` it believes this app speaks (D9's vN-1 case).
     * Absent means "no expectation stated"; a value that is not exactly
     * this app's major degrades the payload instead of refusing it.
     */
    public const string CONTRACT_VERSION_HEADER = 'BFC-Contract-Version';

    public function __invoke(Request $request, CollectVitals $collect): JsonResponse
    {
        DB::transaction(function () use ($request): void {
            app(LifecycleEventRecorder::class)->record(
                event: LifecycleEventType::SensitiveRead,
                credentialId: $this->actingCredentialId($request),
                actor: $this->actor($request),
                note: 'console vitals read (GET /bfc/console/vitals)',
                drainAfterCommit: false,
            );
        });

        return response()->json($collect($request->header(self::CONTRACT_VERSION_HEADER))->toArray());
    }

    /**
     * The acting principal, typed. The id comes from the request
     * attribute the gate stamps on the credential it accepted — so the
     * audit names the credential the GATE authorized, never a second
     * resolution that could disagree with it.
     *
     * Null is unreachable behind this route's middleware (the gate
     * aborts without a credential) and is handled rather than asserted:
     * an untyped actor is a worse outcome than a missing one, and the
     * package never guesses an actor it cannot read.
     */
    private function actor(Request $request): ?AuditActor
    {
        $id = $this->actingCredentialId($request);

        return $id === null ? null : AuditActor::operatorIntegration($id);
    }

    private function actingCredentialId(Request $request): ?string
    {
        $id = $request->attributes->get('bfc.actor_credential_id');

        return is_string($id) && $id !== '' ? $id : null;
    }
}
