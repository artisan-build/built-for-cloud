<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Hmac;

use ArtisanBuild\BuiltForCloud\Actions\RotateCredential;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\CredentialSummary;
use ArtisanBuild\BuiltForCloud\DeliveryShape;
use ArtisanBuild\BuiltForCloud\Exceptions\SigningRootRefused;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\MintResult;
use ArtisanBuild\BuiltForCloud\RotationResult;
use ArtisanBuild\BuiltForCloud\SubjectType;
use Illuminate\Support\Facades\DB;

final class SigningRootLifecycle
{
    public function __construct(private readonly HmacKeyring $keyring) {}

    public function provision(): MintResult
    {
        return app(HmacWriterBarrier::class)->exclusive('signing-root provisioning', fn (): MintResult => DB::transaction(function (): MintResult {
            $this->lockInstallation();

            if ($this->currentRoots()->count() !== 0) {
                throw SigningRootRefused::alreadyProvisioned();
            }

            return new MintResult($this->summary($this->createRoot()), DeliveryShape::None);
        }));
    }

    public function rotate(string $id, bool $emergency, ?AuditActor $actor = null): RotationResult
    {
        return app(HmacWriterBarrier::class)->exclusive('signing-root rotation', fn (): RotationResult => DB::transaction(function () use ($id, $emergency): RotationResult {
            $this->lockInstallation();

            $current = $this->currentRoots();

            if ($current->count() !== 1 || $current->first()?->id !== $id) {
                throw SigningRootRefused::unavailable();
            }

            /** @var Credential $source */
            $source = $current->first();
            $replacement = $this->createRoot();
            $graceEnd = $emergency ? now() : now()->addSeconds(RotateCredential::GRACE_SECONDS);

            if ($source->expires_at !== null && $source->expires_at->isBefore($graceEnd)) {
                $graceEnd = $source->expires_at;
            }

            $source->forceFill([
                'rotated_at' => now(),
                'expires_at' => $graceEnd,
            ])->save();

            if ($this->currentRoots()->count() !== 1) {
                throw SigningRootRefused::unavailable();
            }

            return new RotationResult(
                new MintResult($this->summary($replacement), DeliveryShape::None),
                $source->id,
            );
        }));
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
            'activated_at' => now(),
            'secret_ciphertext' => $encrypted->ciphertext,
            'secret_key_version' => $encrypted->keyVersion,
        ])->save();

        return $root->refresh();
    }

    private function currentRoots(): \Illuminate\Database\Eloquent\Collection
    {
        return Credential::query()
            ->where('kind', CredentialKind::Hmac->value)
            ->where('purpose', CredentialPurpose::SigningRoot->value)
            ->where('subject_type', SubjectType::Installation->value)
            ->where('subject_ref', SigningRootMac::SUBJECT_REF)
            ->whereNull('rotated_at')
            ->active()
            ->lockForUpdate()
            ->get();
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

    private function summary(Credential $credential): CredentialSummary
    {
        return CredentialSummary::fromCredential($credential, null);
    }
}
