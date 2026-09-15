<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Actions\MintCredential;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

final readonly class CredentialAuthorizationExchange
{
    public function __construct(
        private MintCredential $mint,
        private LifecycleEventRecorder $recorder,
    ) {}

    public function exchange(
        Request $request,
        object $authorization,
        CredentialAuthorizationProfile $profile,
        CredentialPurpose $purpose,
    ): CredentialAuthorizationToken {
        $abilities = json_decode((string) $authorization->abilities, true, flags: JSON_THROW_ON_ERROR);
        $result = ($this->mint)(
            $profile->scope->subject,
            new MintOptions(
                kind: CredentialKind::Bearer,
                purpose: $purpose,
                name: is_string($authorization->label) ? $authorization->label : null,
                abilities: $abilities === [] ? null : $abilities,
                expiresAt: $profile->expiresAt,
                userId: $profile->ownership === CredentialAuthorizationOwnership::Personal
                    ? (string) $authorization->initiating_user_id
                    : null,
                boundScope: $profile->scope,
            ),
            AuditActor::credentialHolder((string) $authorization->id),
            credentialAuthorizationId: (string) $authorization->id,
        );
        $secret = $result->secret;

        if ($secret === null) {
            throw new \LogicException('A bearer mint must produce a reveal-once secret.');
        }

        DB::table('credential_authorizations')->where('id', $authorization->id)->update([
            'status' => CredentialAuthorizationStatus::Consumed->value,
            'consumed_at' => now(),
            'issued_credential_id' => $result->summary->id,
            'updated_at' => now(),
        ]);
        $this->recorder->record(
            LifecycleEventType::Exchanged,
            $result->summary->id,
            actor: AuditActor::credentialHolder((string) $authorization->id),
            credentialAuthorizationId: (string) $authorization->id,
        );

        return new CredentialAuthorizationToken(
            $secret,
            $result->summary->id,
            (string) $authorization->app_purpose,
            $profile->expiresAt,
        );
    }
}
