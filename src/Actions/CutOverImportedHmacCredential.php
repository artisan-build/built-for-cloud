<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Actions;

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
use ArtisanBuild\BuiltForCloud\CutOverImportedHmacResult;
use ArtisanBuild\BuiltForCloud\Exceptions\HmacCredentialTransferRefused;
use ArtisanBuild\BuiltForCloud\IssuerHmacCutoverReceipt;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use Illuminate\Support\Facades\DB;

/** Applies an authenticated issuer deadline to the receiver's durable lineage. */
final class CutOverImportedHmacCredential
{
    public function __construct(
        private readonly LifecycleEventRecorder $recorder,
        private readonly AppPurposeRegistry $appPurposes,
    ) {}

    public function __invoke(
        BoundCredentialScope $expectedScope,
        IssuerHmacCutoverReceipt $receipt,
    ): CutOverImportedHmacResult {
        if ($this->appPurposes->purpose($expectedScope->appPurpose) !== CredentialPurpose::Signing
            || ! $this->sameScope($expectedScope, $receipt->scope)
            || $receipt->predecessorCredentialId === null
            || $receipt->predecessorExpiresAt === null) {
            throw new HmacCredentialTransferRefused;
        }

        return DB::transaction(function () use ($expectedScope, $receipt): CutOverImportedHmacResult {
            $ids = [$receipt->predecessorCredentialId, $receipt->replacementCredentialId];
            sort($ids, SORT_STRING);
            $credentials = [];

            foreach ($ids as $id) {
                /** @var Credential|null $credential */
                $credential = Credential::query()->whereKey($id)->lockForUpdate()->first();

                if ($credential === null) {
                    throw new HmacCredentialTransferRefused;
                }

                $credentials[$id] = $credential;
            }

            $bindings = [];

            foreach ($ids as $id) {
                /** @var CredentialProtocolBinding|null $binding */
                $binding = CredentialProtocolBinding::query()->whereKey($id)->lockForUpdate()->first();

                if ($binding === null) {
                    throw new HmacCredentialTransferRefused;
                }

                $bindings[$id] = $binding;
            }

            $predecessor = $credentials[$receipt->predecessorCredentialId];
            $replacement = $credentials[$receipt->replacementCredentialId];

            foreach ([$predecessor, $replacement] as $credential) {
                if ($credential->kind !== CredentialKind::Hmac
                    || $credential->status !== CredentialStatus::Active
                    || $credential->revoked_at !== null
                    || ! $bindings[$credential->id]->exactlyMatches(
                        $credential,
                        $expectedScope,
                        CredentialPurpose::Signing,
                        CredentialAlgorithm::HmacSha256,
                        CredentialMaterialRole::VerificationCopy,
                    )) {
                    throw new HmacCredentialTransferRefused;
                }
            }

            if (! $this->lineageMatches($predecessor->id, $replacement->id)) {
                throw new HmacCredentialTransferRefused;
            }

            $deadline = $receipt->predecessorExpiresAt;
            $current = $predecessor->expires_at?->toImmutable();
            $note = 'imported cutover deadline '.$deadline->toRfc3339String();
            $reason = $receipt->emergency ? AuditReason::Emergency : AuditReason::CutoverCompletion;
            $alreadyRecorded = CredentialAuditEvent::query()
                ->where('credential_id', $predecessor->id)
                ->where('superseded_by_credential_id', $replacement->id)
                ->where('event', LifecycleEventType::Rotated->value)
                ->where('reason_code', $reason->value)
                ->where('note', $note)
                ->exists();

            if ($current !== null && $deadline->greaterThan($current)) {
                throw new HmacCredentialTransferRefused;
            }

            if ($current === null || $deadline->lessThan($current)) {
                Credential::query()->whereKey($predecessor->id)->update(['expires_at' => $deadline]);
            }

            if (! $alreadyRecorded) {
                $this->recorder->record(
                    LifecycleEventType::Rotated,
                    $predecessor->id,
                    reason: $reason,
                    note: $note,
                    supersededByCredentialId: $replacement->id,
                );
            }

            return new CutOverImportedHmacResult(
                $predecessor->id,
                $replacement->id,
                $expectedScope,
                $deadline,
            );
        });
    }

    private function lineageMatches(string $predecessorId, string $replacementId): bool
    {
        return CredentialAuditEvent::query()
            ->where('credential_id', $predecessorId)
            ->where('superseded_by_credential_id', $replacementId)
            ->where('event', LifecycleEventType::Rotated->value)
            ->exists();
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
