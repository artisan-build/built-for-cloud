<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Hmac;

use ArtisanBuild\BuiltForCloud\Actions\RotateCredential;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\AuditReason;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\CredentialSummary;
use ArtisanBuild\BuiltForCloud\DeliveryShape;
use ArtisanBuild\BuiltForCloud\Exceptions\SigningRootRefused;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\MintResult;
use ArtisanBuild\BuiltForCloud\RotationResult;
use ArtisanBuild\BuiltForCloud\SubjectType;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Facades\DB;
use Throwable;

final class SigningRootLifecycle
{
    public function __construct(
        private readonly HmacKeyring $keyring,
        private readonly LifecycleEventRecorder $recorder,
    ) {}

    public function provision(?AuditActor $actor = null): MintResult
    {
        return app(HmacWriterBarrier::class)->exclusive(
            'signing-root provisioning',
            fn (): MintResult => DB::transaction(function () use ($actor): MintResult {
                $this->lockInstallation();

                if ($this->currentCandidates()->isNotEmpty()) {
                    throw SigningRootRefused::alreadyProvisioned();
                }

                $root = $this->createRoot();

                $this->recorder->record(
                    event: LifecycleEventType::Issued,
                    credentialId: $root->id,
                    actor: $actor,
                );

                return new MintResult($this->summary($root), DeliveryShape::None);
            }),
        );
    }

    public function ensure(?AuditActor $actor = null): MintResult
    {
        return app(HmacWriterBarrier::class)->exclusive(
            'signing-root ensure',
            fn (): MintResult => DB::transaction(function () use ($actor): MintResult {
                $this->lockInstallation();

                $reserved = SigningRootMac::reservedCandidates()->lockForUpdate()->get();

                if ($reserved->isEmpty()) {
                    $root = $this->createRoot();

                    $this->recorder->record(
                        event: LifecycleEventType::Issued,
                        credentialId: $root->id,
                        actor: $actor,
                    );

                    return new MintResult($this->summary($root), DeliveryShape::None);
                }

                $current = $this->currentCandidates();
                $root = $current->first();

                if ($root === null || ! $this->isSafeExistingState($reserved, $current, $root)) {
                    throw SigningRootRefused::unavailable();
                }

                return new MintResult($this->summary($root), DeliveryShape::None);
            }),
        );
    }

    public function rotate(string $id, bool $emergency, ?AuditActor $actor = null): RotationResult
    {
        return app(HmacWriterBarrier::class)->exclusive(
            'signing-root rotation',
            fn (): RotationResult => DB::transaction(function () use ($id, $emergency, $actor): RotationResult {
                $this->lockInstallation();

                $current = $this->currentCandidates();
                $source = $current->first();

                if ($current->count() !== 1
                    || $source === null
                    || $source->id !== $id
                    || ! $this->hasExactIdentity($source)) {
                    throw SigningRootRefused::unavailable();
                }

                $cutover = now();
                $replacement = $this->createRoot();
                $graceEnd = $emergency
                    ? $cutover
                    : $cutover->copy()->addSeconds(RotateCredential::GRACE_SECONDS);

                if ($source->expires_at !== null && $source->expires_at->isBefore($graceEnd)) {
                    $graceEnd = $source->expires_at;
                }

                $source->forceFill([
                    'rotated_at' => $cutover,
                    'expires_at' => $graceEnd,
                ])->save();

                $standing = $this->currentCandidates();

                if ($standing->count() !== 1 || $standing->first()?->id !== $replacement->id) {
                    throw SigningRootRefused::unavailable();
                }

                $reason = $emergency ? AuditReason::Emergency : AuditReason::Rotation;

                $this->recorder->record(
                    event: LifecycleEventType::Issued,
                    credentialId: $replacement->id,
                    actor: $actor,
                    reason: $reason,
                );
                $this->recorder->record(
                    event: LifecycleEventType::Rotated,
                    credentialId: $source->id,
                    actor: $actor,
                    reason: $reason,
                    supersededByCredentialId: $replacement->id,
                );

                return new RotationResult(
                    mint: new MintResult($this->summary($replacement), DeliveryShape::None),
                    supersededId: $source->id,
                );
            }),
        );
    }

    private function createRoot(): Credential
    {
        $encrypted = $this->keyring->encrypt(bin2hex(random_bytes(32)));
        $root = new Credential;
        $root->forceFill([
            'kind' => CredentialKind::Hmac,
            'purpose' => CredentialPurpose::SigningRoot,
            'subject_type' => SubjectType::Installation,
            'subject_ref' => SigningRootMac::SUBJECT_REF,
            'abilities' => null,
            'status' => CredentialStatus::Active,
            'secret_ciphertext' => $encrypted->ciphertext,
            'secret_key_version' => $encrypted->keyVersion,
        ])->save();

        return $root->refresh();
    }

    /** @return Collection<int, Credential> */
    private function currentCandidates(): Collection
    {
        return SigningRootMac::currentCandidates()->lockForUpdate()->get();
    }

    private function lockInstallation(): void
    {
        $locked = DB::table('bfc_authority')
            ->where('key', InstallationAuthority::KEY)
            ->lockForUpdate()
            ->first();

        if ($locked === null) {
            throw SigningRootRefused::unavailable();
        }
    }

    private function hasExactIdentity(Credential $root): bool
    {
        return $root->kind === CredentialKind::Hmac
            && $root->purpose === CredentialPurpose::SigningRoot
            && $root->subject_type === SubjectType::Installation
            && $root->subject_ref === SigningRootMac::SUBJECT_REF
            && $root->abilities === null
            && $root->user_id === null
            && $root->secret_ciphertext !== null;
    }

    /**
     * @param  Collection<int, Credential>  $reserved
     * @param  Collection<int, Credential>  $current
     */
    private function isSafeExistingState(Collection $reserved, Collection $current, Credential $root): bool
    {
        if ($current->count() !== 1 || ! $this->isValidCurrentRoot($root)) {
            return false;
        }

        foreach ($reserved as $candidate) {
            if ($candidate->id === $root->id) {
                continue;
            }

            if (! $this->isCompletedHistoricalRoot($candidate)) {
                return false;
            }
        }

        return true;
    }

    private function isValidCurrentRoot(Credential $root): bool
    {
        if (! $this->hasExactStoredIdentity($root)) {
            return false;
        }

        try {
            $plaintext = $this->keyring->decrypt(
                (string) $root->getRawOriginal('secret_ciphertext'),
                $root->getRawOriginal('secret_key_version'),
            );
        } catch (Throwable) {
            return false;
        }

        return preg_match('/^[a-f0-9]{64}$/D', $plaintext) === 1;
    }

    private function isCompletedHistoricalRoot(Credential $root): bool
    {
        try {
            return $this->hasExactStoredIdentity($root)
                && $root->status === CredentialStatus::Active
                && $root->revoked_at === null
                && $root->rotated_at !== null
                && $root->expires_at !== null
                && ! $root->expires_at->isFuture();
        } catch (Throwable) {
            return false;
        }
    }

    private function hasExactStoredIdentity(Credential $root): bool
    {
        $attributes = $root->getAttributes();

        return ($attributes['kind'] ?? null) === CredentialKind::Hmac->value
            && ($attributes['purpose'] ?? null) === CredentialPurpose::SigningRoot->value
            && ($attributes['subject_type'] ?? null) === SubjectType::Installation->value
            && ($attributes['subject_ref'] ?? null) === SigningRootMac::SUBJECT_REF
            && ($attributes['abilities'] ?? null) === null
            && ($attributes['user_id'] ?? null) === null
            && is_string($attributes['secret_ciphertext'] ?? null)
            && $attributes['secret_ciphertext'] !== ''
            && is_string($attributes['secret_key_version'] ?? null)
            && $attributes['secret_key_version'] !== '';
    }

    private function summary(Credential $credential): CredentialSummary
    {
        return CredentialSummary::fromCredential($credential, null);
    }
}
