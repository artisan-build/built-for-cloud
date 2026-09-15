<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Actions;

use ArtisanBuild\BuiltForCloud\AppPurposeRegistry;
use ArtisanBuild\BuiltForCloud\AuditActor;
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
use ArtisanBuild\BuiltForCloud\EnrolledAsymmetricCredential;
use ArtisanBuild\BuiltForCloud\Exceptions\AsymmetricEnrollmentUnavailable;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\Rs256PublicKey;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use SensitiveParameter;
use Throwable;
use ValueError;

final class CompleteAsymmetricEnrollment
{
    public function __construct(
        private readonly LifecycleEventRecorder $recorder,
        private readonly AppPurposeRegistry $appPurposes,
    ) {}

    public function __invoke(
        #[SensitiveParameter] string $enrollmentCode,
        BoundCredentialScope $expectedScope,
        Rs256PublicKey $publicKey,
    ): EnrolledAsymmetricCredential {
        $purpose = $this->appPurposes->purpose($expectedScope->appPurpose);

        if ($purpose !== CredentialPurpose::Signing) {
            throw InvalidCredentialInput::boundScopeMismatch();
        }

        try {
            /** @var EnrolledAsymmetricCredential */
            return DB::transaction(fn (): EnrolledAsymmetricCredential => $this->complete(
                $enrollmentCode,
                $expectedScope,
                $publicKey,
                $purpose,
            ));
        } catch (AsymmetricEnrollmentUnavailable $exception) {
            throw $exception;
        } catch (QueryException $exception) {
            $state = $exception->errorInfo[0] ?? $exception->getCode();

            if (in_array((string) $state, ['40001', '40P01'], true)) {
                throw new AsymmetricEnrollmentUnavailable;
            }

            throw $exception;
        } catch (ValueError) {
            throw new AsymmetricEnrollmentUnavailable;
        }
    }

    private function complete(
        #[SensitiveParameter] string $enrollmentCode,
        BoundCredentialScope $scope,
        Rs256PublicKey $publicKey,
        CredentialPurpose $purpose,
    ): EnrolledAsymmetricCredential {
        /** @var OnboardingToken|null $token */
        $token = OnboardingToken::query()
            ->where('token_hash', OnboardingToken::hashToken($enrollmentCode))
            ->lockForUpdate()
            ->first();

        if ($token === null
            || $token->consumed_at !== null
            || ! $token->expires_at->isAfter(now())
            || $token->durable_credential_id === null) {
            throw new AsymmetricEnrollmentUnavailable;
        }

        $credentialId = $token->durable_credential_id;
        $predecessorId = $this->predecessorOf($credentialId);
        $credentialIds = array_values(array_unique(array_filter([$credentialId, $predecessorId])));
        sort($credentialIds, SORT_STRING);
        $credentials = [];

        foreach ($credentialIds as $id) {
            /** @var Credential|null $credential */
            $credential = Credential::query()->whereKey($id)->lockForUpdate()->first();

            if ($credential === null) {
                throw new AsymmetricEnrollmentUnavailable;
            }

            $credentials[$id] = $credential;
        }

        $bindings = [];

        foreach ($credentialIds as $id) {
            $binding = DB::table('credential_protocol_bindings')->where('credential_id', $id)->lockForUpdate()->first();

            if ($binding === null) {
                throw new AsymmetricEnrollmentUnavailable;
            }

            $bindings[$id] = $binding;
        }

        $credential = $credentials[$credentialId];

        if (! $this->bindingMatches($bindings[$credentialId], $credential, $scope, $purpose)
            || $credential->kind !== CredentialKind::Asymmetric
            || $credential->purpose !== CredentialPurpose::Signing
            || $credential->status !== CredentialStatus::Pending
            || $credential->user_id !== null
            || $credential->revoked_at !== null
            || ($credential->expires_at !== null && ! $credential->expires_at->isAfter(now()))
            || $credential->public_key !== null) {
            throw new AsymmetricEnrollmentUnavailable;
        }

        if ($predecessorId !== null) {
            $predecessor = $credentials[$predecessorId];

            if ($this->currentSuccessorOf($predecessorId) !== $credentialId
                || ! $this->bindingMatches($bindings[$predecessorId], $predecessor, $scope, $purpose)) {
                throw new AsymmetricEnrollmentUnavailable;
            }
        }

        $consumed = OnboardingToken::query()
            ->whereKey($token->id)
            ->whereNull('consumed_at')
            ->update(['consumed_at' => now()]);

        if ($consumed !== 1) {
            throw new AsymmetricEnrollmentUnavailable;
        }

        Credential::query()->whereKey($credentialId)->update([
            'public_key' => $publicKey->pem,
            'status' => CredentialStatus::Active->value,
            'activated_at' => now(),
        ]);

        $actor = AuditActor::credentialHolder($token->id);
        $this->recorder->record(LifecycleEventType::Exchanged, $credentialId, $token->id, $actor);
        $this->recorder->record(LifecycleEventType::Activated, $credentialId, $token->id, $actor);

        if ($predecessorId !== null) {
            $graceEnd = now()->addSeconds(RotateCredential::GRACE_SECONDS);
            Credential::query()
                ->whereKey($predecessorId)
                ->where(function ($query) use ($graceEnd): void {
                    $query->whereNull('expires_at')->orWhere('expires_at', '>', $graceEnd);
                })
                ->update(['expires_at' => $graceEnd]);
            $this->recorder->record(
                LifecycleEventType::Rotated,
                $predecessorId,
                actor: $actor,
                reason: AuditReason::CutoverCompletion,
                supersededByCredentialId: $credentialId,
            );
        }

        return new EnrolledAsymmetricCredential(
            $credentialId,
            $scope->appPurpose,
            $scope->subject,
            $scope->installation,
            $scope->application,
            $scope->audience,
            CredentialAlgorithm::Rs256,
        );
    }

    private function predecessorOf(string $credentialId): ?string
    {
        $ids = CredentialAuditEvent::query()
            ->where('event', LifecycleEventType::Rotated->value)
            ->where('superseded_by_credential_id', $credentialId)
            ->pluck('credential_id')
            ->filter(static fn (mixed $id): bool => is_string($id) && $id !== '')
            ->unique()
            ->values();

        if ($ids->count() > 1) {
            throw new AsymmetricEnrollmentUnavailable;
        }

        $id = $ids->first();

        return is_string($id) ? $id : null;
    }

    private function currentSuccessorOf(string $predecessorId): ?string
    {
        $candidateIds = CredentialAuditEvent::query()
            ->where('credential_id', $predecessorId)
            ->where('event', LifecycleEventType::Rotated->value)
            ->pluck('superseded_by_credential_id')
            ->filter(static fn (mixed $id): bool => is_string($id) && $id !== '')
            ->unique()
            ->values();
        $abandoned = CredentialAuditEvent::query()
            ->whereIn('credential_id', $candidateIds->all())
            ->where('event', LifecycleEventType::Revoked->value)
            ->where('reason_code', AuditReason::DeliveryAbandoned->value)
            ->pluck('credential_id')
            ->all();
        $live = $candidateIds->reject(static fn (string $id): bool => in_array($id, $abandoned, true))->values();

        return $live->count() === 1 && is_string($live->first()) ? $live->first() : null;
    }

    private function bindingMatches(
        object $binding,
        Credential $credential,
        BoundCredentialScope $scope,
        CredentialPurpose $purpose,
    ): bool {
        $algorithm = CredentialAlgorithm::Rs256;
        $role = CredentialMaterialRole::Originator;

        return $credential->subject_type === $scope->subject->type
            && hash_equals($credential->subject_ref, $scope->subject->ref)
            && $credential->purpose === $purpose
            && is_string($binding->app_purpose ?? null)
            && hash_equals($binding->app_purpose, $scope->appPurpose)
            && is_string($binding->installation_ref ?? null)
            && hash_equals($binding->installation_ref, $scope->installation)
            && is_string($binding->application_ref ?? null)
            && hash_equals($binding->application_ref, $scope->application)
            && is_string($binding->audience ?? null)
            && hash_equals($binding->audience, $scope->audience)
            && ($binding->algorithm ?? null) === $algorithm->value
            && ($binding->material_role ?? null) === $role->value
            && is_string($binding->scope_hash ?? null)
            && hash_equals($binding->scope_hash, CredentialProtocolBinding::scopeHash($scope, $purpose, $algorithm, $role));
    }
}
