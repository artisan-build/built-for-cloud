<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use LogicException;

final readonly class CredentialAuthorizationTransitions
{
    public function __construct(private LifecycleEventRecorder $recorder) {}

    public function deny(object $authorization, CredentialAuthorizationDenialReason $reason, ?AuditActor $actor = null): bool
    {
        if (! in_array($authorization->status, [CredentialAuthorizationStatus::Pending->value, CredentialAuthorizationStatus::Approved->value], true)) {
            return false;
        }

        $changed = \Illuminate\Support\Facades\DB::table('credential_authorizations')
            ->where('id', $authorization->id)
            ->whereIn('status', [CredentialAuthorizationStatus::Pending->value, CredentialAuthorizationStatus::Approved->value])
            ->update([
                'status' => CredentialAuthorizationStatus::Denied->value,
                'denial_reason' => $reason->value,
                'decided_at' => now(),
                'updated_at' => now(),
            ]);

        if ($changed !== 1) {
            return false;
        }

        if (\Illuminate\Support\Facades\DB::transactionLevel() === 0) {
            throw new LogicException('Authorization denial must share its caller transaction.');
        }

        $this->recorder->record(
            LifecycleEventType::CredentialAuthorizationDenied,
            actor: $actor,
            credentialAuthorizationId: (string) $authorization->id,
        );

        return true;
    }
}
