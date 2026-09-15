<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Actions;

use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationAuthority;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationDecision;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationDenialReason;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationFlow;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationPolicy;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationStatus;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationTransitions;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialAuthorizationRefused;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\MintedSecret;
use ArtisanBuild\BuiltForCloud\SubmissionNonce;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

final readonly class DecideLoopbackAuthorization
{
    public function __construct(
        private CredentialAuthorizationPolicy $policy,
        private CredentialAuthorizationTransitions $transitions,
        private LifecycleEventRecorder $recorder,
    ) {}

    public function __invoke(
        Request $request,
        string $authorizationId,
        string $browserNonce,
        string $state,
        bool $approve,
        ?SubmissionNonce $submission = null,
    ): CredentialAuthorizationDecision {
        $result = DB::transaction(function () use ($request, $authorizationId, $browserNonce, $state, $approve, $submission): CredentialAuthorizationDecision|CredentialAuthorizationRefused {
            $authorization = DB::table('credential_authorizations')->where('id', $authorizationId)->lockForUpdate()->first();
            $user = $request->user();

            if (! is_object($authorization)
                || $authorization->flow !== CredentialAuthorizationFlow::Loopback->value
                || $authorization->status !== CredentialAuthorizationStatus::Pending->value
                || ! $user instanceof Authenticatable
                || (string) $user->getAuthIdentifier() !== $authorization->initiating_user_id
                || ! hash_equals((string) $authorization->browser_session_nonce_hash, hash('sha256', $browserNonce))
                || now()->greaterThanOrEqualTo($authorization->expires_at)) {
                return CredentialAuthorizationRefused::unavailable();
            }

            try {
                [$profile] = $this->policy->revalidate($request, $authorization);
            } catch (CredentialAuthorizationRefused) {
                $this->transitions->deny($authorization, CredentialAuthorizationDenialReason::ProfileWithdrawn, AuditActor::boundUser((string) $authorization->initiating_user_id));

                return CredentialAuthorizationRefused::unavailable();
            }

            $authority = $this->policy->authority($profile, $request, (string) $authorization->initiating_user_id);

            if ($authority === CredentialAuthorizationAuthority::Unavailable) {
                throw CredentialAuthorizationRefused::temporarilyUnavailable();
            }

            if ($authority === CredentialAuthorizationAuthority::Denied) {
                $this->transitions->deny($authorization, CredentialAuthorizationDenialReason::AuthorityDenied, AuditActor::boundUser((string) $authorization->initiating_user_id));

                return new CredentialAuthorizationDecision(
                    $authorizationId,
                    CredentialAuthorizationStatus::Denied,
                    redirectUri: (string) $authorization->redirect_uri,
                    state: $state,
                );
            }

            $submission?->consume();

            if (! $approve) {
                $this->transitions->deny($authorization, CredentialAuthorizationDenialReason::UserDenied, AuditActor::boundUser((string) $authorization->initiating_user_id));

                return new CredentialAuthorizationDecision(
                    $authorizationId,
                    CredentialAuthorizationStatus::Denied,
                    redirectUri: (string) $authorization->redirect_uri,
                    state: $state,
                );
            }

            $code = new MintedSecret(self::opaqueCode());
            DB::table('credential_authorizations')->where('id', $authorizationId)->update([
                'status' => CredentialAuthorizationStatus::Approved->value,
                'authorization_code_hash' => $code->hash(),
                'decided_at' => now(),
                'updated_at' => now(),
            ]);
            $this->recorder->record(
                LifecycleEventType::CredentialAuthorizationApproved,
                actor: AuditActor::boundUser((string) $authorization->initiating_user_id),
                credentialAuthorizationId: $authorizationId,
            );

            return new CredentialAuthorizationDecision(
                $authorizationId,
                CredentialAuthorizationStatus::Approved,
                $code,
                (string) $authorization->redirect_uri,
                $state,
            );
        });

        if ($result instanceof CredentialAuthorizationRefused) {
            throw $result;
        }

        return $result;
    }

    private static function opaqueCode(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }
}
