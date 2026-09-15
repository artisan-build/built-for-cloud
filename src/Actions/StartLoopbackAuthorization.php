<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Actions;

use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\BrowserCredentialAuthorizationStore;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationAuthority;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationFlow;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationPolicy;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationStatus;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialAuthorizationRefused;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\LoopbackAuthorizationIntent;
use ArtisanBuild\BuiltForCloud\LoopbackRedirectUri;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

final readonly class StartLoopbackAuthorization
{
    public function __construct(
        private CredentialAuthorizationPolicy $policy,
        private BrowserCredentialAuthorizationStore $browser,
        private LifecycleEventRecorder $recorder,
    ) {}

    public function __invoke(
        Request $authenticatedRequest,
        string $appPurpose,
        string $redirectUri,
        string $codeChallenge,
        string $codeChallengeMethod,
        string $state,
        ?string $label = null,
    ): LoopbackAuthorizationIntent {
        $redirect = new LoopbackRedirectUri($redirectUri);

        if ($codeChallengeMethod !== 'S256'
            || preg_match('/\A[A-Za-z0-9_-]{43}\z/D', $codeChallenge) !== 1
            || strlen((string) base64_decode(strtr($codeChallenge, '-_', '+/').'=', true)) !== 32
            || preg_match('/\A[A-Za-z0-9._~-]{32,128}\z/D', $state) !== 1) {
            throw CredentialAuthorizationRefused::invalidRequest();
        }

        [$profile, $purpose, $userId] = $this->policy->start($authenticatedRequest, $appPurpose);
        $authority = $this->policy->authority($profile, $authenticatedRequest, $userId);

        if ($authority !== CredentialAuthorizationAuthority::Allowed) {
            throw $authority === CredentialAuthorizationAuthority::Denied
                ? CredentialAuthorizationRefused::denied()
                : CredentialAuthorizationRefused::temporarilyUnavailable();
        }

        $label = $this->policy->label($label);
        $browserNonce = self::opaqueCode();
        $authorizationId = (string) Str::uuid();

        DB::transaction(function () use ($authenticatedRequest, $profile, $purpose, $userId, $label, $redirect, $codeChallenge, $state, $browserNonce, $authorizationId): void {
            DB::table('credential_authorizations')->insert([
                'id' => $authorizationId,
                'flow' => CredentialAuthorizationFlow::Loopback->value,
                'redirect_uri' => $redirect->value,
                'pkce_challenge' => $codeChallenge,
                'status' => CredentialAuthorizationStatus::Pending->value,
                'app_purpose' => $profile->appPurpose,
                'protocol_purpose' => $purpose->value,
                'subject_type' => $profile->scope->subject->type->value,
                'subject_ref' => $profile->scope->subject->ref,
                'installation_ref' => $profile->scope->installation,
                'application_ref' => $profile->scope->application,
                'audience' => $profile->scope->audience,
                'ownership' => $profile->ownership->value,
                'abilities' => json_encode($this->policy->canonicalAbilities($profile->abilities), JSON_THROW_ON_ERROR),
                'label' => $label,
                'credential_expires_at' => $profile->expiresAt,
                'initiating_user_id' => $userId,
                'browser_session_nonce_hash' => hash('sha256', $browserNonce),
                'expires_at' => now()->addSeconds($profile->codeTtlSeconds),
                'created_at' => now(),
                'updated_at' => now(),
            ]);
            $this->browser->put($authenticatedRequest, $authorizationId, [
                'flow' => CredentialAuthorizationFlow::Loopback->value,
                'nonce' => $browserNonce,
                'state' => $state,
            ]);
            $this->recorder->record(
                LifecycleEventType::CredentialAuthorizationStarted,
                actor: AuditActor::boundUser($userId),
                credentialAuthorizationId: $authorizationId,
            );
        });

        return new LoopbackAuthorizationIntent($authorizationId, $appPurpose, $redirect->value, $state);
    }

    private static function opaqueCode(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }
}
