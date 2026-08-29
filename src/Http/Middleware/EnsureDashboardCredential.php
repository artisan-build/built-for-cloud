<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Middleware;

use ArtisanBuild\BuiltForCloud\ApiToken;
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
 *  2. **A bearer that is not ALSO something else.** Before anything is
 *     resolved, the presented bytes are compared against the configured
 *     `FALLBACK_TOKEN` and against the legacy `api_tokens` store; a
 *     match is refused.
 *
 *     This is not belt-and-braces. The `bfc` guard has no code path to
 *     either store, so neither can authenticate a request HERE — and
 *     that fact, which an earlier docblock stated as if it settled
 *     something, is beside the point. The danger runs the other way:
 *     set `FALLBACK_TOKEN` to the plaintext of a real exact-
 *     `{metadata:read}` credential (or file the same bytes as a legacy
 *     admin token) and the dashboard read succeeds while the SAME bytes
 *     stay admin-equivalent on the legacy surfaces. D16 requires the
 *     dashboard credential to be unable to touch mutating surfaces;
 *     aliased bytes can, so the alias is what has to be refused.
 *
 *     The check is deliberately side-effect-free — a digest comparison
 *     and one existence query, no usage stamped, no client identity
 *     observed, no row resolved — and its answer is the ordinary 401,
 *     because telling a caller "these bytes are also something else" is
 *     the one thing an aliasing probe wants to learn.
 *
 *  3. **An authenticated unified-store credential.** The guard resolves
 *     that store only, and an expired, revoked or offboarded principal
 *     resolves to nothing. Every one of those is the same 401.
 *  4. **The app's declaration authorizing it** for `metadata:read` —
 *     the hook {@see EnsureCredentialAbility} calls, kept because an app
 *     narrowing its own credentials must be able to narrow this one too.
 *  5. **An operator subject.** The contract heads this route "operator
 *     credential"; the ability vocabulary is an operator vocabulary, and
 *     a credential minted for an application principal is not an
 *     operator however its abilities list reads.
 *  6. **An ability set exactly equal to `{metadata:read}`.** Not a
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
        // BEFORE anything resolves. An aliased bearer must not stamp
        // usage, observe a client identity or touch a row on its way to
        // being refused, and it must be refused with the same answer an
        // unknown one gets.
        if ($this->isAliased((string) $request->bearerToken())) {
            abort(401);
        }

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
     * Whether these bearer bytes are ALSO the configured fallback token
     * or a row in the legacy `api_tokens` store.
     *
     * Side-effect-free by construction: a constant-time digest
     * comparison, then one `exists()` query on a hashed column. Nothing
     * is resolved, stamped or observed, so an aliasing probe learns
     * nothing from timing a row it cannot see and nothing from the
     * response, which is the ordinary 401.
     *
     * EVERY legacy row counts, revoked and expired included. A revoked
     * row is not usable on the legacy surfaces today, but the question
     * here is not "can these bytes act elsewhere right now" — it is
     * whether this deployment has ever filed them as something else. A
     * dashboard credential whose bytes are on file in a second store is
     * not the least-privilege credential D16 describes, whatever that
     * store's row currently says.
     */
    private function isAliased(string $bearer): bool
    {
        if ($bearer === '') {
            return false;
        }

        $fallback = config('built-for-cloud.fallback_token');

        if (is_string($fallback)
            && $fallback !== ''
            && hash_equals(hash('sha256', $fallback), hash('sha256', $bearer))) {
            return true;
        }

        return ApiToken::query()->where('token_hash', hash('sha256', $bearer))->exists();
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
