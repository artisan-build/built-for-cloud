<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Actions;

use ArtisanBuild\BuiltForCloud\AuditReason;
use ArtisanBuild\BuiltForCloud\BoundCredentialScope;
use ArtisanBuild\BuiltForCloud\ClaimedHmacCredential;
use ArtisanBuild\BuiltForCloud\Contracts\HmacCredentialIssuerClient;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAlgorithm;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialMaterialRole;
use ArtisanBuild\BuiltForCloud\CredentialProtocolBinding;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\Exceptions\HmacCredentialTransferRefused;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use ArtisanBuild\BuiltForCloud\Hmac\HmacWriterBarrier;
use ArtisanBuild\BuiltForCloud\InstalledHmacCredential;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\SensitiveString;
use ArtisanBuild\BuiltForCloud\UiCredentialPurposes;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use SensitiveParameter;

/** Installs one authenticated issuer delivery as an encrypted verification copy. */
final class InstallHmacCredentialFromClaim
{
    public function __construct(
        private readonly LifecycleEventRecorder $recorder,
        private readonly UiCredentialPurposes $purposes,
        private readonly HmacKeyring $keyring,
        private readonly HmacWriterBarrier $barrier,
    ) {}

    public function __invoke(
        BoundCredentialScope $expectedScope,
        HmacCredentialIssuerClient $trustedIssuer,
        #[SensitiveParameter] string $claimCode,
    ): InstalledHmacCredential {
        $purpose = $this->purposes->purposeForSubmission($expectedScope->appPurpose);

        if ($purpose !== CredentialPurpose::Signing) {
            throw new HmacCredentialTransferRefused;
        }

        $claimed = $trustedIssuer->claim($expectedScope, new SensitiveString($claimCode));
        $transfer = $claimed->transfer;

        if (! $this->sameScope($expectedScope, $transfer->scope)
            || $transfer->algorithm !== CredentialAlgorithm::HmacSha256->value
            || $transfer->sourceStatus !== CredentialStatus::Pending
            || ! Str::isUuid($transfer->issuerCredentialId)
            || $transfer->deliveryGeneration < 1
            || preg_match('/\A[0-9a-f]{16}\z/D', $transfer->deliveryFingerprint) !== 1
            || $transfer->deliveredAt->isFuture()
            || now()->greaterThan($transfer->transferExpiresAt)
            || $transfer->transferExpiresAt->greaterThan($transfer->deliveredAt->addSeconds(60))
            || ($transfer->credentialExpiresAt !== null && ! $transfer->credentialExpiresAt->isFuture())) {
            throw new HmacCredentialTransferRefused;
        }

        $deliveryValidated = false;

        try {
            return $this->barrier->exclusive('HMAC credential installation', function () use ($expectedScope, $claimed, &$deliveryValidated): InstalledHmacCredential {
                return DB::transaction(function () use ($expectedScope, $claimed, &$deliveryValidated): InstalledHmacCredential {
                    return $this->install($expectedScope, $claimed, $deliveryValidated);
                });
            });
        } catch (QueryException $failure) {
            $state = (string) ($failure->errorInfo[0] ?? $failure->getCode());

            if (! $deliveryValidated || ! in_array($state, ['23000', '23505', '40001', '40P01'], true)) {
                throw $failure;
            }

            return $this->idempotentResult($expectedScope, $transfer->issuerCredentialId, $transfer->deliveryFingerprint, $transfer->predecessorCredentialId)
                ?? throw new HmacCredentialTransferRefused;
        }
    }

    private function install(BoundCredentialScope $scope, ClaimedHmacCredential $claimed, bool &$deliveryValidated): InstalledHmacCredential
    {
        $transfer = $claimed->transfer;
        $ids = array_values(array_filter([$transfer->predecessorCredentialId, $transfer->issuerCredentialId]));
        sort($ids, SORT_STRING);
        $locked = [];

        foreach ($ids as $id) {
            /** @var Credential|null $credential */
            $credential = Credential::query()->whereKey($id)->lockForUpdate()->first();
            $locked[$id] = $credential;
        }

        $plaintext = $claimed->secret->reveal();

        if (preg_match('/\A[0-9a-f]{64}\z/D', $plaintext) !== 1
            || ! hash_equals($transfer->deliveryFingerprint, $this->keyring->deliveryFingerprint($plaintext, $transfer->deliveryGeneration))) {
            throw new HmacCredentialTransferRefused;
        }

        $deliveryValidated = true;
        $existing = $locked[$transfer->issuerCredentialId] ?? null;

        if ($existing !== null) {
            unset($plaintext);

            return $this->idempotentResult($scope, $transfer->issuerCredentialId, $transfer->deliveryFingerprint, $transfer->predecessorCredentialId)
                ?? throw new HmacCredentialTransferRefused;
        }

        $predecessor = $transfer->predecessorCredentialId === null
            ? null
            : ($locked[$transfer->predecessorCredentialId] ?? null);

        if (($transfer->predecessorCredentialId !== null && ! $predecessor instanceof Credential)
            || ($predecessor instanceof Credential && ! $this->validPredecessor($predecessor, $scope, $transfer->deliveryGeneration))) {
            throw new HmacCredentialTransferRefused;
        }

        $encrypted = $this->keyring->encrypt($plaintext);
        unset($plaintext);

        $credential = new Credential;
        $credential->forceFill([
            'id' => $transfer->issuerCredentialId,
            'kind' => CredentialKind::Hmac,
            'purpose' => CredentialPurpose::Signing,
            'subject_type' => $scope->subject->type,
            'subject_ref' => $scope->subject->ref,
            'status' => CredentialStatus::Active,
            'secret_ciphertext' => $encrypted->ciphertext,
            'secret_key_version' => $encrypted->keyVersion,
            'delivered_at' => $transfer->deliveredAt,
            'delivered_generation' => $transfer->deliveryGeneration,
            'delivery_fingerprint' => $transfer->deliveryFingerprint,
            'activated_at' => now(),
            'expires_at' => $transfer->credentialExpiresAt,
        ])->save();
        CredentialProtocolBinding::createVerificationCopy($credential, $scope);

        $this->recorder->record(LifecycleEventType::Issued, $credential->id, credentialExpiresAt: $credential->expires_at);
        $this->recorder->record(
            LifecycleEventType::Delivered,
            $credential->id,
            note: 'imported delivery generation '.$transfer->deliveryGeneration.' ('.$transfer->deliveryFingerprint.')',
        );
        $this->recorder->record(
            LifecycleEventType::Activated,
            $credential->id,
            note: 'receiver confirmed delivery generation '.$transfer->deliveryGeneration.' ('.$transfer->deliveryFingerprint.')',
        );

        if ($predecessor instanceof Credential) {
            $this->recorder->record(
                LifecycleEventType::Rotated,
                $predecessor->id,
                reason: AuditReason::Rotation,
                supersededByCredentialId: $credential->id,
            );
        }

        return new InstalledHmacCredential($credential->id, $predecessor?->id, $scope);
    }

    private function validPredecessor(Credential $credential, BoundCredentialScope $scope, int $generation): bool
    {
        /** @var CredentialProtocolBinding|null $binding */
        $binding = CredentialProtocolBinding::query()->whereKey($credential->id)->lockForUpdate()->first();

        return $credential->kind === CredentialKind::Hmac
            && $credential->status === CredentialStatus::Active
            && $credential->revoked_at === null
            && ($credential->expires_at === null || $credential->expires_at->isFuture())
            && $credential->delivered_generation <= $generation
            && $binding !== null
            && $binding->exactlyMatches(
                $credential,
                $scope,
                CredentialPurpose::Signing,
                CredentialAlgorithm::HmacSha256,
                CredentialMaterialRole::VerificationCopy,
            );
    }

    private function idempotentResult(
        BoundCredentialScope $scope,
        string $credentialId,
        string $fingerprint,
        ?string $predecessorId,
    ): ?InstalledHmacCredential {
        /** @var Credential|null $credential */
        $credential = Credential::query()->whereKey($credentialId)->first();
        /** @var CredentialProtocolBinding|null $binding */
        $binding = CredentialProtocolBinding::query()->whereKey($credentialId)->first();

        if ($credential === null
            || $binding === null
            || $credential->kind !== CredentialKind::Hmac
            || $credential->status !== CredentialStatus::Active
            || ! is_string($credential->delivery_fingerprint)
            || ! hash_equals($credential->delivery_fingerprint, $fingerprint)
            || ! $binding->exactlyMatches(
                $credential,
                $scope,
                CredentialPurpose::Signing,
                CredentialAlgorithm::HmacSha256,
                CredentialMaterialRole::VerificationCopy,
            )
            || ! $this->lineageMatches($predecessorId, $credentialId)) {
            return null;
        }

        return new InstalledHmacCredential($credentialId, $predecessorId, $scope);
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

    private function sameScope(BoundCredentialScope $left, BoundCredentialScope $right): bool
    {
        return $left->subject->type === $right->subject->type
            && hash_equals($left->subject->ref, $right->subject->ref)
            && hash_equals($left->appPurpose, $right->appPurpose)
            && hash_equals($left->installation, $right->installation)
            && hash_equals($left->application, $right->application)
            && hash_equals($left->audience, $right->audience);
    }
}
