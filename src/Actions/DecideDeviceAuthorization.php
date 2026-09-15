<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Actions;

use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\BrowserCredentialAuthorizationStore;
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
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

final readonly class DecideDeviceAuthorization
{
    public function __construct(
        private CredentialAuthorizationPolicy $policy,
        private BrowserCredentialAuthorizationStore $browser,
        private CredentialAuthorizationTransitions $transitions,
        private LifecycleEventRecorder $recorder,
    ) {}

    public function __invoke(Request $request, string $userCode, bool $approve): CredentialAuthorizationDecision
    {
        $userCode = self::normalizeUserCode($userCode);
        $binding = $this->browser->findDevice($request, $userCode);

        if ($binding === null) {
            throw CredentialAuthorizationRefused::unavailable();
        }

        [$authorizationId, $payload] = $binding;

        $result = DB::transaction(function () use ($request, $userCode, $approve, $authorizationId, $payload): CredentialAuthorizationDecision|CredentialAuthorizationRefused {
            $authorization = DB::table('credential_authorizations')->where('id', $authorizationId)->lockForUpdate()->first();
            $user = $request->user();

            if (! is_object($authorization)
                || $authorization->flow !== CredentialAuthorizationFlow::Device->value
                || $authorization->status !== CredentialAuthorizationStatus::Pending->value
                || ! $user instanceof Authenticatable
                || (string) $user->getAuthIdentifier() !== $authorization->initiating_user_id
                || ! isset($payload['nonce'])
                || ! hash_equals((string) $authorization->browser_session_nonce_hash, hash('sha256', $payload['nonce']))
                || ! hash_equals((string) $authorization->user_code_hash, hash('sha256', $userCode))
                || now()->greaterThanOrEqualTo($authorization->expires_at)) {
                return CredentialAuthorizationRefused::unavailable();
            }

            try {
                [$profile] = $this->policy->revalidate($request, $authorization);
            } catch (CredentialAuthorizationRefused) {
                $this->transitions->deny($authorization, CredentialAuthorizationDenialReason::ProfileWithdrawn, AuditActor::boundUser((string) $authorization->initiating_user_id));
                $this->browser->forget($request, $authorizationId);

                return CredentialAuthorizationRefused::unavailable();
            }

            $authority = $this->policy->authority($profile, $request, (string) $authorization->initiating_user_id);

            if ($authority === CredentialAuthorizationAuthority::Unavailable) {
                throw CredentialAuthorizationRefused::temporarilyUnavailable();
            }

            if ($authority === CredentialAuthorizationAuthority::Denied) {
                $this->transitions->deny($authorization, CredentialAuthorizationDenialReason::AuthorityDenied, AuditActor::boundUser((string) $authorization->initiating_user_id));
                $this->browser->forget($request, $authorizationId);

                return CredentialAuthorizationRefused::unavailable();
            }

            if (! $approve) {
                $this->transitions->deny($authorization, CredentialAuthorizationDenialReason::UserDenied, AuditActor::boundUser((string) $authorization->initiating_user_id));
                $this->browser->forget($request, $authorizationId);

                return new CredentialAuthorizationDecision($authorizationId, CredentialAuthorizationStatus::Denied);
            }

            DB::table('credential_authorizations')->where('id', $authorizationId)->update([
                'status' => CredentialAuthorizationStatus::Approved->value,
                'decided_at' => now(),
                'updated_at' => now(),
            ]);
            $this->recorder->record(
                LifecycleEventType::CredentialAuthorizationApproved,
                actor: AuditActor::boundUser((string) $authorization->initiating_user_id),
                credentialAuthorizationId: $authorizationId,
            );
            $this->browser->forget($request, $authorizationId);

            return new CredentialAuthorizationDecision($authorizationId, CredentialAuthorizationStatus::Approved);
        });

        if ($result instanceof CredentialAuthorizationRefused) {
            throw $result;
        }

        return $result;
    }

    public static function normalizeUserCode(string $userCode): string
    {
        $userCode = strtoupper(trim($userCode, " \t\n\r\0\x0B"));

        if (preg_match('/\A[A-HJ-NP-Z2-9]{8}\z/D', $userCode) === 1) {
            return substr($userCode, 0, 4).'-'.substr($userCode, 4);
        }

        if (preg_match('/\A[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}\z/D', $userCode) !== 1) {
            throw CredentialAuthorizationRefused::unavailable();
        }

        return $userCode;
    }
}
