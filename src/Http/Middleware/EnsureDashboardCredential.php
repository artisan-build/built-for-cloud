<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Middleware;

use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\Auth\CredentialGuard;
use ArtisanBuild\BuiltForCloud\Contracts\ConstrainsMintedCredentials;
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
 * The EXCLUSIVITY half of the Console dashboard gate (Console PRD D16).
 * It runs INSIDE {@see EnsureCredentialAbility}, which has already
 * established that the presenting credential holds `metadata:read`, and
 * adds the two requirements membership alone cannot express.
 *
 * D16 does not say "a credential that has `metadata:read`". It says the
 * dashboard credential is "least-privilege, read-audited, **unable to
 * touch content-classified or mutating surfaces**", and it FORBIDS using
 * the ownership/admin credential for any dashboard read path. A
 * credential holding `{metadata:read, credential:admin}` satisfies a
 * membership check and violates every word of that: it reads the
 * dashboard AND mutates every operator surface. Inability has to be a
 * property of the CREDENTIAL, not of the route, because the credential
 * is what the vendor holds and what an attacker steals.
 *
 * So this gate requires:
 *
 *  1. **An operator subject.** The contract heads this route "operator
 *     credential", and until now nothing checked it — an
 *     application-subject credential holding the ability read vitals.
 *     {@see EnsureCredentialAdmin} makes the same check on the verb
 *     routes; the ability vocabulary is an OPERATOR vocabulary, and a
 *     credential minted for an application principal is not an operator
 *     however its abilities list reads.
 *  2. **An ability set exactly equal to `{metadata:read}`.** Not a
 *     superset. This is the "unable to touch" clause, enforced rather
 *     than described.
 *
 * WHAT THIS DOES NOT DO, named because an unlisted gap reads as a
 * covered one: it does not stop such a credential being MINTED. A
 * combined credential can still be issued and can still operate every
 * other surface it names; what it cannot do is read the dashboard. Mint
 * ceilings are a declaration concern
 * ({@see ConstrainsMintedCredentials}),
 * and refusing the combination at issue time is a separate decision with
 * its own upgrade consequences for credentials already in the field.
 *
 * A refusal here is audited as a `denied_action` with the acting
 * credential, best-effort — the deny must stand even while the audit
 * store is down.
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
        $credential = $this->credential();

        if ($credential === null) {
            // Unreachable behind the ability gate, which aborts without
            // an authenticated credential. Handled rather than asserted,
            // and it fails CLOSED: a gate that cannot see what it is
            // authorizing authorizes nothing.
            abort(401);
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
                'denied: dashboard credential must hold '.OperatorAbility::MetadataRead->value.' and nothing else',
            );

            abort(403);
        }

        return $next($request);
    }

    /**
     * The credential the `bfc` guard already resolved for this request —
     * the guard caches per request, so this is a lookup rather than a
     * second authentication, and it is the SAME credential the ability
     * gate authorized.
     */
    private function credential(): ?Credential
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

        return $guard instanceof CredentialGuard ? $guard->credential() : null;
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
