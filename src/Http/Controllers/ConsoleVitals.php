<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAbility;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin;
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
 * ITS GATE IS `bfc.ability:metadata:read`
 * ({@see EnsureCredentialAbility}), and the choice is D16 itself rather
 * than a style preference. D16 forbids "using the ownership/admin
 * credential for any dashboard read path", and the operator gate
 * ({@see EnsureCredentialAdmin}) cannot enforce that: it grants a
 * `credential:admin` credential whatever ability a route names,
 * unconditionally and without consulting any list, so a break-glass
 * credential would have passed a route mounted behind it. This gate
 * matches EXACTLY — no ability implies another, `credential:admin`
 * included — and it authenticates through the `bfc` guard, which
 * resolves the unified store only, so a legacy admin `api_tokens` secret
 * and a `FALLBACK_TOKEN` never authenticate here at all. The route is
 * consequently reachable by one thing: a live unified-store credential
 * whose own abilities list contains
 * {@see OperatorAbility::MetadataRead}.
 *
 * THE AUDIT IS TRANSACTIONAL, NOT BEST-EFFORT, and it runs BEFORE the
 * payload is assembled. D16's ability is "read-audited"; a vendor read
 * this deployment cannot record is one it should not serve, so the
 * append is the one thing on this route that can turn a vitals request
 * into a 500. That is deliberate and it is not in tension with D9:
 * D9's never-error rule governs what vitals REPORTS about the app's
 * dependencies (an unreachable queue degrades the payload, see
 * {@see CollectVitals}), not whether the read itself is recorded.
 * Running it first also fixes which way the remaining failure leans —
 * a recorded read that then failed to serve, rather than a served read
 * nobody recorded.
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
