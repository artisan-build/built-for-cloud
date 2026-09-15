<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Actions;

use ArtisanBuild\BuiltForCloud\Actions\Concerns\RetiresSupersededCredentials;
use ArtisanBuild\BuiltForCloud\AppPurposeRegistry;
use ArtisanBuild\BuiltForCloud\AuditReason;
use ArtisanBuild\BuiltForCloud\BoundCredentialScope;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAlgorithm;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialMaterialRole;
use ArtisanBuild\BuiltForCloud\CredentialProtocolBinding;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\Exceptions\HmacCredentialTransferRefused;
use ArtisanBuild\BuiltForCloud\IssuerHmacCutoverReceipt;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use Illuminate\Support\Facades\DB;

/** Trusted issuer-side activation and idempotent cutover status projection. */
final class SourceBoundHmacCutover
{
    use RetiresSupersededCredentials;

    public function __construct(
        private readonly ActivateCredential $activateCredential,
        private readonly AppPurposeRegistry $appPurposes,
    ) {}

    public function activate(
        BoundCredentialScope $scope,
        ?string $predecessorId,
        string $replacementId,
        string $deliveryFingerprint,
    ): IssuerHmacCutoverReceipt {
        $this->assertLineage($scope, $predecessorId, $replacementId, CredentialStatus::Pending);
        ($this->activateCredential)($replacementId, $deliveryFingerprint);

        return $this->status($scope, $predecessorId, $replacementId);
    }

    public function status(
        BoundCredentialScope $scope,
        ?string $predecessorId,
        string $replacementId,
    ): IssuerHmacCutoverReceipt {
        return DB::transaction(function () use ($scope, $predecessorId, $replacementId): IssuerHmacCutoverReceipt {
            [$replacement, $predecessor] = $this->assertLineage(
                $scope,
                $predecessorId,
                $replacementId,
                CredentialStatus::Active,
                true,
            );

            if ($replacement->activated_at === null) {
                throw new HmacCredentialTransferRefused;
            }

            if ($predecessor !== null && $predecessor->expires_at === null) {
                if ($predecessor->status !== CredentialStatus::Active || $predecessor->revoked_at !== null) {
                    throw new HmacCredentialTransferRefused;
                }

                $this->retireAt(
                    $predecessor->id,
                    $replacement->activated_at->toImmutable()->addSeconds(RotateCredential::GRACE_SECONDS),
                );
                $predecessor->refresh();

                if ($predecessor->expires_at === null) {
                    throw new HmacCredentialTransferRefused;
                }
            }

            $emergency = $predecessorId !== null && CredentialAuditEvent::query()
                ->where('credential_id', $predecessorId)
                ->where('superseded_by_credential_id', $replacementId)
                ->where('event', LifecycleEventType::Rotated->value)
                ->where('reason_code', AuditReason::Emergency->value)
                ->exists();

            return IssuerHmacCutoverReceipt::fromIssuerResponse(
                $predecessorId,
                $replacementId,
                $scope,
                $replacement->activated_at->toImmutable(),
                $predecessor?->expires_at?->toImmutable(),
                $emergency,
            );
        });
    }

    /** @return array{Credential, Credential|null} */
    private function assertLineage(
        BoundCredentialScope $scope,
        ?string $predecessorId,
        string $replacementId,
        CredentialStatus $replacementStatus,
        bool $lock = false,
    ): array {
        if ($this->appPurposes->purpose($scope->appPurpose) !== CredentialPurpose::Signing) {
            throw new HmacCredentialTransferRefused;
        }

        $ids = array_values(array_filter([$predecessorId, $replacementId]));
        sort($ids, SORT_STRING);
        $credentials = [];

        foreach ($ids as $id) {
            /** @var Credential|null $credential */
            $credential = Credential::query()->whereKey($id)->when($lock, fn ($query) => $query->lockForUpdate())->first();
            $credentials[$id] = $credential;
        }

        /** @var Credential|null $replacement */
        $replacement = $credentials[$replacementId] ?? null;
        /** @var CredentialProtocolBinding|null $replacementBinding */
        $replacementBinding = CredentialProtocolBinding::query()->whereKey($replacementId)->first();
        /** @var Credential|null $predecessor */
        $predecessor = $predecessorId === null ? null : ($credentials[$predecessorId] ?? null);
        /** @var CredentialProtocolBinding|null $predecessorBinding */
        $predecessorBinding = $predecessorId === null ? null : CredentialProtocolBinding::query()->whereKey($predecessorId)->first();

        if ($replacement === null
            || $replacementBinding === null
            || $replacement->kind !== CredentialKind::Hmac
            || $replacement->status !== $replacementStatus
            || $replacement->revoked_at !== null
            || ($replacement->expires_at !== null && ! $replacement->expires_at->isFuture())
            || ! $replacementBinding->exactlyMatches(
                $replacement,
                $scope,
                CredentialPurpose::Signing,
                CredentialAlgorithm::HmacSha256,
                CredentialMaterialRole::Originator,
            )
            || ($predecessorId !== null && ($predecessor === null
                || $predecessorBinding === null
                || $predecessor->kind !== CredentialKind::Hmac
                || ! $predecessorBinding->exactlyMatches(
                    $predecessor,
                    $scope,
                    CredentialPurpose::Signing,
                    CredentialAlgorithm::HmacSha256,
                    CredentialMaterialRole::Originator,
                )))
            || ! $this->lineageMatches($predecessorId, $replacementId)) {
            throw new HmacCredentialTransferRefused;
        }

        return [$replacement, $predecessor];
    }

    private function lineageMatches(?string $predecessorId, string $replacementId): bool
    {
        $predecessors = CredentialAuditEvent::query()
            ->where('event', LifecycleEventType::Rotated->value)
            ->where('superseded_by_credential_id', $replacementId)
            ->pluck('credential_id')
            ->filter(static fn (mixed $id): bool => is_string($id) && $id !== '')
            ->unique()
            ->values()
            ->all();

        return $predecessorId === null ? $predecessors === [] : $predecessors === [$predecessorId];
    }
}
