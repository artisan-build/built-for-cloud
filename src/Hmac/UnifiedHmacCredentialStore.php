<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Hmac;

use ArtisanBuild\BfcClient\BoundCredentialScope;
use ArtisanBuild\BfcClient\Contracts\HmacCredentialStore;
use ArtisanBuild\BfcClient\CredentialMaterialRole;
use ArtisanBuild\BfcClient\CredentialPurpose;
use ArtisanBuild\BfcClient\CredentialStatus;
use ArtisanBuild\BfcClient\Hmac\HmacEnvelope;
use ArtisanBuild\BfcClient\StoredHmacCredential;
use ArtisanBuild\BfcClient\Subject;
use ArtisanBuild\BfcClient\SubjectType;
use ArtisanBuild\BuiltForCloud\AuditReason;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialProtocolBinding;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\ManagedAccountAccess;
use ArtisanBuild\BuiltForCloud\OffboardedSubject;
use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Closure;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use InvalidArgumentException;
use Throwable;
use TypeError;
use ValueError;

final readonly class UnifiedHmacCredentialStore implements HmacCredentialStore
{
    /** @param Closure(): HmacWriterBarrier $writerBarrier */
    public function __construct(
        private LifecycleEventRecorder $recorder,
        private ManagedAccountAccess $managedAccess,
        private Closure $writerBarrier,
    ) {}

    public function transaction(Closure $operation): mixed
    {
        return ($this->writerBarrier)()->exclusive(
            'HMAC credential installation',
            static fn (): mixed => DB::transaction($operation),
        );
    }

    public function find(string $credentialId, bool $lockForUpdate = false): ?StoredHmacCredential
    {
        if (! Schema::hasColumn('credentials', 'purpose')) {
            return null;
        }

        /** @var Credential|null $credential */
        $credential = Credential::query()
            ->whereKey($credentialId)
            ->where('kind', CredentialKind::Hmac->value)
            ->where('purpose', CredentialPurpose::Signing->value)
            ->whereNotNull('secret_ciphertext')
            ->when($lockForUpdate, static fn ($query) => $query->lockForUpdate())
            ->first();

        if (! $credential instanceof Credential) {
            return null;
        }

        /** @var CredentialProtocolBinding|null $binding */
        $binding = CredentialProtocolBinding::query()
            ->whereKey($credential->id)
            ->when($lockForUpdate, static fn ($query) => $query->lockForUpdate())
            ->first();

        try {
            if (OffboardedSubject::rejects($credential)) {
                return null;
            }

            $id = $credential->id;
            $subjectType = $credential->subject_type;
            $status = $credential->status;
            $deliveredAt = self::immutable($credential->delivered_at);
            $activatedAt = self::immutable($credential->activated_at);
            $fingerprint = $credential->delivery_fingerprint;

            if (! is_string($id)
                || ! $subjectType instanceof SubjectType
                || ! $status instanceof CredentialStatus
                || $deliveredAt === null
                || $activatedAt === null
                || ! is_string($fingerprint)) {
                return null;
            }

            $scope = null;
            $role = null;
            $algorithm = HmacEnvelope::ALGORITHM;
            $scopeHash = null;

            if ($binding instanceof CredentialProtocolBinding) {
                $rawAlgorithm = $binding->getRawOriginal('algorithm');
                $rawRole = $binding->getRawOriginal('material_role');
                $rawScopeHash = $binding->getRawOriginal('scope_hash');

                if (! is_string($rawAlgorithm) || ! is_string($rawRole) || ! is_string($rawScopeHash)) {
                    return null;
                }

                $role = CredentialMaterialRole::tryFrom($rawRole);

                if (! $role instanceof CredentialMaterialRole) {
                    return null;
                }

                $scope = new BoundCredentialScope(
                    $binding->app_purpose,
                    new Subject($subjectType, $credential->subject_ref),
                    $binding->installation_ref,
                    $binding->application_ref,
                    $binding->audience,
                );
                $algorithm = $rawAlgorithm;
                $scopeHash = $rawScopeHash;
            }

            return new StoredHmacCredential(
                id: $id,
                purpose: CredentialPurpose::Signing,
                subject: new Subject($subjectType, $credential->subject_ref),
                status: $status,
                secretCiphertext: $credential->secret_ciphertext,
                secretKeyVersion: $credential->secret_key_version,
                deliveredAt: $deliveredAt,
                deliveryGeneration: $credential->delivered_generation,
                deliveryFingerprint: $fingerprint,
                predecessorCredentialId: $this->predecessorId($id),
                activatedAt: $activatedAt,
                expiresAt: self::immutable($credential->expires_at),
                revokedAt: self::immutable($credential->revoked_at),
                scope: $scope,
                materialRole: $role,
                algorithm: $algorithm,
                scopeHash: $scopeHash,
            );
        } catch (InvalidArgumentException|TypeError|ValueError) {
            return null;
        }
    }

    public function insertVerificationCopy(StoredHmacCredential $credential): void
    {
        $scope = $credential->scope;

        if (! $scope instanceof BoundCredentialScope
            || $credential->purpose !== CredentialPurpose::Signing
            || $credential->materialRole !== CredentialMaterialRole::VerificationCopy
            || ! hash_equals($credential->algorithm, HmacEnvelope::ALGORITHM)
            || $credential->scopeHash === null
            || ! hash_equals(
                $credential->scopeHash,
                StoredHmacCredential::scopeHash($scope, CredentialMaterialRole::VerificationCopy),
            )) {
            throw new InvalidArgumentException('The HMAC verification copy does not match the unified store shape.');
        }

        $stored = new Credential;
        $stored->forceFill([
            'id' => $credential->id,
            'kind' => CredentialKind::Hmac,
            'purpose' => CredentialPurpose::Signing,
            'subject_type' => $credential->subject->type,
            'subject_ref' => $credential->subject->ref,
            'status' => $credential->status,
            'secret_ciphertext' => $credential->secretCiphertext,
            'secret_key_version' => $credential->secretKeyVersion,
            'delivered_at' => $credential->deliveredAt,
            'delivered_generation' => $credential->deliveryGeneration,
            'delivery_fingerprint' => $credential->deliveryFingerprint,
            'activated_at' => $credential->activatedAt,
            'expires_at' => $credential->expiresAt,
            'revoked_at' => $credential->revokedAt,
        ])->save();
        CredentialProtocolBinding::createVerificationCopy($stored, $scope);

        $this->recorder->record(
            LifecycleEventType::Issued,
            $stored->id,
            credentialExpiresAt: $stored->expires_at,
        );
        $this->recorder->record(
            LifecycleEventType::Delivered,
            $stored->id,
            note: 'imported delivery generation '.$credential->deliveryGeneration.' ('.$credential->deliveryFingerprint.')',
        );
        $this->recorder->record(
            LifecycleEventType::Activated,
            $stored->id,
            note: 'receiver confirmed delivery generation '.$credential->deliveryGeneration.' ('.$credential->deliveryFingerprint.')',
        );

        if ($credential->predecessorCredentialId !== null) {
            $this->recorder->record(
                LifecycleEventType::Rotated,
                $credential->predecessorCredentialId,
                reason: AuditReason::Rotation,
                supersededByCredentialId: $stored->id,
            );
        }
    }

    public function allowsAfterSignature(StoredHmacCredential $credential): bool
    {
        /** @var Credential|null $stored */
        $stored = Credential::query()->whereKey($credential->id)->first();

        return $stored instanceof Credential
            && hash_equals($stored->id, $credential->id)
            && $this->managedAccess->allowsCredential($stored);
    }

    public function stampUsage(string $credentialId, CarbonImmutable $usedAt): void
    {
        Credential::query()->whereKey($credentialId)->update(['last_used_at' => $usedAt]);
    }

    public function hasKeyVersionOtherThan(string $writeVersion): bool
    {
        return Credential::query()
            ->where('kind', CredentialKind::Hmac->value)
            ->whereNotNull('secret_ciphertext')
            ->where(function ($query) use ($writeVersion): void {
                $query->whereNull('secret_key_version')
                    ->orWhere('secret_key_version', '!=', $writeVersion);
            })
            ->exists();
    }

    public function isConcurrencyConflict(Throwable $failure): bool
    {
        if (! $failure instanceof QueryException) {
            return false;
        }

        $state = (string) ($failure->errorInfo[0] ?? $failure->getCode());

        return in_array($state, ['23000', '23505', '40001', '40P01'], true);
    }

    private function predecessorId(string $replacementId): ?string
    {
        $predecessors = CredentialAuditEvent::query()
            ->where('event', LifecycleEventType::Rotated->value)
            ->where('superseded_by_credential_id', $replacementId)
            ->pluck('credential_id')
            ->filter(static fn (mixed $id): bool => is_string($id) && $id !== '')
            ->unique()
            ->values()
            ->all();

        if ($predecessors === []) {
            return null;
        }

        return count($predecessors) === 1 ? $predecessors[0] : "\0conflicting-lineage";
    }

    private static function immutable(?CarbonInterface $value): ?CarbonImmutable
    {
        return $value === null ? null : CarbonImmutable::instance($value);
    }
}
