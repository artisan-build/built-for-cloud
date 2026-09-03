<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Middleware;

use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\Console\AssertionBurn;
use ArtisanBuild\BuiltForCloud\Console\AssertionPurpose;
use ArtisanBuild\BuiltForCloud\Console\AssertionVerifier;
use ArtisanBuild\BuiltForCloud\Console\ConsoleEntryRefusalReason;
use ArtisanBuild\BuiltForCloud\Console\DelegatedActor;
use ArtisanBuild\BuiltForCloud\Console\RequestAssertion;
use ArtisanBuild\BuiltForCloud\Exceptions\AssertionRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\ConsoleEntryRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\DelegatedActorDeactivated;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\TokenRegistry;
use Carbon\CarbonImmutable;
use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use SensitiveParameter;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * Authenticate one stateless MCP request with either a registry token or a
 * delegated assertion.
 *
 * `Authorization: Bearer` is exclusive and prefix-discriminated. A bearer
 * beginning `v4.public.` is verified only as an assertion; every other bearer
 * is resolved only by TokenRegistry. Neither failure falls through to the
 * other path.
 *
 * Assertion handling mirrors the console entry door: verify, require the MCP
 * purpose, commit the handoff record independently, then burn and lock-check
 * the actor in this middleware's transaction before publishing a principal on
 * this request object. Assertion refusals are audited and fail closed if that
 * audit cannot be committed. Registry-token refusals are intentionally not
 * audited here, matching the package's public bearer gates.
 */
final class AuthenticateMcp
{
    public const int REFUSAL_STATUS = 401;

    public const string AUDIT_NOTE = 'mcp authentication refused: ';

    public function __construct(
        private readonly TokenRegistry $tokens,
        private readonly AssertionVerifier $verifier,
        private readonly LifecycleEventRecorder $recorder,
    ) {}

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(#[SensitiveParameter] Request $request, Closure $next): Response
    {
        $bearer = $request->bearerToken();

        // Remove the live credential before any validation or storage path
        // can throw and a rich exception reporter can serialize the request.
        $request->headers->remove('Authorization');

        if ($bearer === null || $bearer === '') {
            return $this->refuseToken();
        }

        if (str_starts_with($bearer, AssertionVerifier::HEADER)) {
            return $this->authenticateAssertion($request, $next, $bearer);
        }

        $token = $this->tokens->resolveModel($bearer);

        if ($token === null) {
            return $this->refuseToken();
        }

        $this->tokens->recordClientIdentityFromRequest($request, $token);

        // The attribute keeps its ONE meaning — an ADMIN token
        // authenticated, EnsureAdminToken's convention: the package's
        // readers convert it straight into AuditActor::adminToken(),
        // which types the audit row AdminToken. A non-admin MCP token
        // still authenticates this door, but must not arrive anywhere
        // wearing an attribution its credential does not hold.
        if ($token->hasScope(Scope::Admin)) {
            $request->attributes->set('bfc.actor_token_id', (string) $token->getKey());
        }

        $request->setUserResolver(static fn () => $token);

        return $next($request);
    }

    /**
     * @param  Closure(Request): Response  $next
     */
    private function authenticateAssertion(
        #[SensitiveParameter] Request $request,
        Closure $next,
        #[SensitiveParameter] string $assertionToken,
    ): Response {
        $mintId = null;

        try {
            $assertion = $this->verifier->verify($assertionToken);
            $mintId = $assertion->id;

            if ($assertion->purpose !== AssertionPurpose::Mcp) {
                throw ConsoleEntryRefused::because(ConsoleEntryRefusalReason::PurposeMismatch, $assertion->id);
            }

            // Its own commit: containment must not erase evidence that this
            // actor attempted entry or the claims that attempt carried.
            $actor = DelegatedActor::recordHandoff($assertion);

            DB::transaction(function () use ($request, $assertion, $actor): void {
                AssertionBurn::burn($assertion, CarbonImmutable::now());

                $locked = DelegatedActor::lockedById($actor->getKey());

                if (! $locked instanceof DelegatedActor || ! $locked->isActive()) {
                    throw DelegatedActorDeactivated::cannotEnter();
                }

                RequestAssertion::publish($request, $locked, $assertion);
            });

            $this->prune();

            return $next($request);
        } catch (AssertionRefused $refused) {
            return $this->refuseAssertion($refused->reason->value, null);
        } catch (ConsoleEntryRefused $refused) {
            return $this->refuseAssertion($refused->reason->value, $refused->assertionId);
        } catch (DelegatedActorDeactivated) {
            return $this->refuseAssertion(ConsoleEntryRefusalReason::ActorDeactivated->value, $mintId);
        }
    }

    private function refuseToken(): JsonResponse
    {
        return response()->json(['message' => 'Unauthenticated.'], self::REFUSAL_STATUS);
    }

    private function refuseAssertion(string $reason, ?string $mintId): JsonResponse
    {
        DB::transaction(function () use ($reason, $mintId): void {
            $this->recorder->record(
                event: LifecycleEventType::DeniedAction,
                actor: AuditActor::assertionPresenter($mintId),
                note: self::AUDIT_NOTE.$reason,
                drainAfterCommit: false,
            );
        });

        return $this->refuseToken();
    }

    private function prune(): void
    {
        try {
            AssertionBurn::prune(CarbonImmutable::now());
        } catch (Throwable) {
            // Housekeeping cannot fail an authenticated request.
        }
    }
}
