<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Actions;

use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\BrowserCredentialAuthorizationStore;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationAuthority;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationFlow;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationPolicy;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationStatus;
use ArtisanBuild\BuiltForCloud\DeviceAuthorizationStart;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialAuthorizationRefused;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\MintedSecret;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

final readonly class StartDeviceAuthorization
{
    private const string USER_CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

    public function __construct(
        private CredentialAuthorizationPolicy $policy,
        private LifecycleEventRecorder $recorder,
        private BrowserCredentialAuthorizationStore $browser,
    ) {}

    public function __invoke(Request $authenticatedRequest, string $appPurpose, ?string $label = null): DeviceAuthorizationStart
    {
        [$profile, $purpose, $userId] = $this->policy->start($authenticatedRequest, $appPurpose);
        $authority = $this->policy->authority($profile, $authenticatedRequest, $userId);

        if ($authority === CredentialAuthorizationAuthority::Denied) {
            throw CredentialAuthorizationRefused::denied();
        }

        if ($authority === CredentialAuthorizationAuthority::Unavailable) {
            throw CredentialAuthorizationRefused::temporarilyUnavailable();
        }

        $label = $this->policy->label($label);

        if (! $this->browser->hasCapacity($authenticatedRequest)) {
            throw CredentialAuthorizationRefused::temporarilyUnavailable();
        }

        $deviceCode = self::opaqueCode();
        $userCode = self::userCode();
        $browserNonce = self::opaqueCode();
        $authorizationId = (string) Str::uuid();
        $expiresAt = now()->addSeconds($profile->codeTtlSeconds);

        DB::transaction(function () use ($authenticatedRequest, $profile, $purpose, $userId, $label, $deviceCode, $userCode, $browserNonce, $authorizationId, $expiresAt): void {
            DB::table('credential_authorizations')->insert([
                'id' => $authorizationId,
                'flow' => CredentialAuthorizationFlow::Device->value,
                'device_code_hash' => hash('sha256', $deviceCode),
                'user_code_hash' => hash('sha256', $userCode),
                'status' => CredentialAuthorizationStatus::Pending->value,
                ...$this->snapshot($profile, $purpose->value, $userId, $label, $browserNonce),
                'base_interval' => $profile->initialPollInterval,
                'effective_interval' => $profile->initialPollInterval,
                'expires_at' => $expiresAt,
                'created_at' => now(),
                'updated_at' => now(),
            ]);
            $this->recorder->record(
                LifecycleEventType::CredentialAuthorizationStarted,
                actor: AuditActor::boundUser($userId),
                credentialAuthorizationId: $authorizationId,
            );
            $this->browser->putDevice($authenticatedRequest, $authorizationId, $browserNonce, $userCode);
        });

        return new DeviceAuthorizationStart(
            $authorizationId,
            new MintedSecret($deviceCode),
            new MintedSecret($userCode),
            new MintedSecret($browserNonce),
            url('/bfc/device'),
            $profile->codeTtlSeconds,
            $profile->initialPollInterval,
        );
    }

    private static function opaqueCode(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    private static function userCode(): string
    {
        $value = '';

        for ($i = 0; $i < 8; $i++) {
            $value .= self::USER_CODE_ALPHABET[random_int(0, strlen(self::USER_CODE_ALPHABET) - 1)];
        }

        return substr($value, 0, 4).'-'.substr($value, 4);
    }

    /** @return array<string, mixed> */
    private function snapshot(object $profile, string $purpose, string $userId, ?string $label, string $browserNonce): array
    {
        return [
            'app_purpose' => $profile->appPurpose,
            'protocol_purpose' => $purpose,
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
            'profile_code_ttl_seconds' => $profile->codeTtlSeconds,
            'profile_initial_poll_interval' => $profile->initialPollInterval,
        ];
    }
}
