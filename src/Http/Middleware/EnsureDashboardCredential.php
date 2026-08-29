<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Middleware;

use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\Auth\CredentialGuard;
use ArtisanBuild\BuiltForCloud\Contracts\ConstrainsMintedCredentials;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\SubjectType;
use Closure;
use Illuminate\Auth\AuthManager;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * The COMPLETE gate on the Console dashboard read (Console PRD D16). It
 * is the only middleware between the throttle and the controller, and
 * that is deliberate rather than tidy.
 *
 * An earlier revision composed it with `bfc.ability:metadata:read` and
 * added the two checks that gate could not express. The composition was
 * the bug. On an authenticated request {@see EnsureCredentialAbility}
 * enforces a strict SUBSET of what this class does — its membership
 * check is implied by the exact-set check below, and its declaration
 * check is the same call — so the outer layer never changed an answer,
 * while its own denial audit drains the delivery outbox. That put the
 * amplification lever this route was hardened against back onto the
 * REFUSAL path, which is the path an attacker can reach at will. A
 * redundant gate is not free; it is a second code path with its own
 * side effects.
 *
 * (One request it answered differently, and worse: with no `bfc` guard
 * configured it raised out of the AuthManager, so a package-mounted
 * route 500'd on an app that never registered one. This gate answers a
 * bounded 401.)
 *
 * WHAT IT REQUIRES, in order, each failing closed:
 *
 *  1. **A `bfc` guard that exists.** A package-mounted route may not
 *     depend on the consuming app having registered one; a name with no
 *     guard behind it is a bounded 401, not a 500 out of the AuthManager.
 *  2. **An authenticated unified-store credential.** The guard resolves
 *     that store only, so a legacy admin `api_tokens` secret and a
 *     `FALLBACK_TOKEN` never authenticate here at all, and an expired,
 *     revoked or offboarded principal resolves to nothing. Every one of
 *     those is the same 401.
 *  3. **The app's declaration authorizing it** for `metadata:read` —
 *     the hook {@see EnsureCredentialAbility} calls, kept because an app
 *     narrowing its own credentials must be able to narrow this one too.
 *  4. **An operator subject.** The contract heads this route "operator
 *     credential"; the ability vocabulary is an operator vocabulary, and
 *     a credential minted for an application principal is not an
 *     operator however its abilities list reads.
 *  5. **An ability set exactly equal to `{metadata:read}`.** Not a
 *     superset. D16 does not say "a credential that has
 *     `metadata:read`"; it says the dashboard credential is
 *     "least-privilege, read-audited, **unable to touch
 *     content-classified or mutating surfaces**", and it FORBIDS using
 *     the ownership/admin credential for any dashboard read path. A
 *     credential holding `{metadata:read, credential:admin}` satisfies a
 *     membership check and violates every word of that. Inability has to
 *     be a property of the CREDENTIAL, because the credential is what
 *     the vendor holds and what an attacker steals.
 *
 * WHAT IT DOES NOT DO, named because an unlisted gap reads as a covered
 * one: it does not stop such a credential being MINTED. A combined
 * credential can still be issued and can still operate every other
 * surface it names; what it cannot do is read the dashboard. Mint
 * ceilings are a declaration concern ({@see ConstrainsMintedCredentials}),
 * and refusing the combination at issue time is a separate decision with
 * its own upgrade consequences for credentials already in the field.
 *
 * EVERY denial here is audited as a `denied_action` with the acting
 * credential where there is one, best-effort — the deny must stand even
 * while the audit store is down — and with `drainAfterCommit: false`,
 * because this route is polled and a drain walks every claimable row and
 * may send mail. The denial branch is the one an attacker can reach at
 * will, so it is the branch that most needed it.
 */
final class EnsureDashboardCredential
{
    /**
     * The exact ability set a dashboard credential may carry.
     *
     * @var list<string>
     */
    public const array ABILITIES = [OperatorAbility::MetadataRead->value];

    public function __construct(private readonly AuthManager $auth) {}

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $guard = $this->guard();

        if ($guard === null) {
            // No `bfc` guard configured under the name this package
            // reads. An operator misconfiguration, and still a request
            // that cannot be authenticated: it fails closed with the
            // same 401 an unknown credential gets. The diagnostic cost
            // is stated rather than hidden — the operator has to look at
            // `auth.guards` to tell the two apart.
            abort(401);
        }

        if ($guard->guest()) {
            // Anonymous denials are deliberately NOT audited: this route
            // is unauthenticated-reachable, and auditing strangers would
            // hand them a database-write amplifier on the one branch
            // they can reach without a credential.
            abort(401);
        }

        $credential = $guard->credential();

        if ($credential === null) {
            abort(401);
        }

        $ability = OperatorAbility::MetadataRead->value;

        if (! app(CredentialDeclaration::class)->authorize($credential, $ability, $request)) {
            $this->auditDenial($request, $credential, 'denied: the app declaration refused '.$ability);

            abort(403);
        }

        if ($credential->subject_type !== SubjectType::Operator) {
            $this->auditDenial($request, $credential, 'denied: dashboard read requires an operator subject');

            abort(403);
        }

        $abilities = $credential->abilities ?? [];

        sort($abilities);

        $expected = self::ABILITIES;
        sort($expected);

        if ($abilities !== $expected) {
            $this->auditDenial(
                $request,
                $credential,
                'denied: dashboard credential must hold '.$ability.' and nothing else',
            );

            abort(403);
        }

        // Which credential this gate accepted, for the controller's
        // audit — the same attribute name and meaning
        // {@see EnsureCredentialAdmin} sets, so the read is attributed
        // to the credential the GATE authorized rather than to a second
        // resolution that could disagree with it.
        $request->attributes->set('bfc.actor_credential_id', $credential->id);

        return $next($request);
    }

    /**
     * The `bfc` guard, or null when the app has not registered one.
     * Structural absence and a guard that throws are the same answer
     * here: a gate that cannot see what it is authorizing authorizes
     * nothing.
     */
    private function guard(): ?CredentialGuard
    {
        $guardName = (string) config('built-for-cloud.credentials.guard', 'bfc');

        if (! is_array(config('auth.guards.'.$guardName))) {
            return null;
        }

        try {
            $guard = $this->auth->guard($guardName);
        } catch (Throwable) {
            return null;
        }

        return $guard instanceof CredentialGuard ? $guard : null;
    }

    private function auditDenial(Request $request, Credential $credential, string $note): void
    {
        try {
            DB::transaction(function () use ($request, $credential, $note): void {
                app(LifecycleEventRecorder::class)->record(
                    event: LifecycleEventType::DeniedAction,
                    credentialId: $credential->id,
                    actor: AuditActor::operatorIntegration($credential->id),
                    note: $note.' ('.$request->method().' /'.$request->path().')',
                    drainAfterCommit: false,
                );
            });
        } catch (Throwable) {
            // Losing the audit row must not convert a deny into a 500.
        }
    }
}
