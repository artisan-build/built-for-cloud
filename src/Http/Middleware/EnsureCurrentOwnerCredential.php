<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Middleware;

use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\Auth\CredentialResolver;
use ArtisanBuild\BuiltForCloud\ClientIdentityRecorder;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\CredentialUsageRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\Ownership;
use ArtisanBuild\BuiltForCloud\StandaloneRouteOwnership;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * The gate on the managed-enrolment routes (P1): the bearer must be
 * THE CURRENT OWNERSHIP-LINKED credential — the one `POST
 * /bfc/ownership/claim` minted and `bfc_ownership.owner_credential_id`
 * names — not merely any credential carrying `credential:admin`. The
 * enrolment verbs re-shape the installation's whole authority mode, so
 * their caller is the owner and nobody else: a different live operator
 * credential, admin or not, is an authenticated non-owner (403).
 *
 * Failure ladder mirrors {@see EnsureCredentialAdmin}: a missing,
 * unknown, wrong-purpose or dead token is an anonymous 401; a working
 * credential that is not the owner credential is a scope failure
 * (403), audited as a denied action with ids only. Uses are recorded
 * through the same recorder (the stamp re-asserts the row still
 * authenticates), and the accepted row is visible downstream as
 * `bfc.actor_credential_id`.
 */
final class EnsureCurrentOwnerCredential
{
    public function __construct(
        private readonly CredentialResolver $credentials,
        private readonly CredentialUsageRecorder $usage,
        private readonly ClientIdentityRecorder $clientIdentities,
    ) {}

    /** @param Closure(Request): Response $next */
    public function handle(Request $request, Closure $next): Response
    {
        $bearer = $request->bearerToken();

        if ($bearer === null || $bearer === '') {
            $this->clientIdentities->observeUnauthenticatedClientIdentity($request);
            $this->auditDenial($request, 'token_auth_failure: no credential presented', null);

            abort(401);
        }

        $credential = $this->credentials->resolve(CredentialKind::Bearer, $bearer);

        if ($credential !== null && $credential->purpose !== CredentialPurpose::OperatorManagement) {
            // A secret valid for another protocol is anonymous here — no
            // use stamp, no client-identity observation, no oracle.
            abort(401);
        }

        if ($credential === null) {
            $this->clientIdentities->observeUnauthenticatedClientIdentity($request);
            $this->auditDenial($request, 'token_auth_failure: unknown credential', null);

            abort(401);
        }

        if (! $this->usage->recordUsage($credential)) {
            $this->auditDenial($request, 'token_auth_failure: credential died before use', null);

            abort(401);
        }

        $ownerCredentialId = Ownership::current()?->owner_credential_id;

        if (! is_string($ownerCredentialId) || $ownerCredentialId !== $credential->id) {
            // It authenticated, so this is a scope failure, not an
            // unknown: an owner-shaped credential that is not THE owner
            // credential of this installation.
            $this->clientIdentities->recordClientIdentityFromRequest($request, $credential);
            $this->auditDenial($request, 'denied: credential is not the current owner credential', AuditActor::operatorIntegration($credential->id));

            abort(403);
        }

        $this->clientIdentities->recordClientIdentityFromRequest($request, $credential);

        $request->attributes->set('bfc.actor_credential_id', $credential->id);
        StandaloneRouteOwnership::markOperatorGateExecuted($request, self::class);

        return $next($request);
    }

    /** Best-effort denial audit, ids only — the DENY stands even if this write fails. */
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
            // The denial response is the containment.
        }
    }
}
