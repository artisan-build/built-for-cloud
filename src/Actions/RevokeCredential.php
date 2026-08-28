<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Actions;

use ArtisanBuild\BuiltForCloud\Actions\Concerns\ConsultsDeclaration;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\AuditReason;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialVerb;
use ArtisanBuild\BuiltForCloud\DurableStore;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialVerbRefused;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\RevokeOutcome;
use Illuminate\Support\Facades\DB;

/**
 * The revoke verb over the unified store (PRD 1.0), by id — the precise
 * verb — consumed by both `bfc:credential:revoke --local` and
 * `DELETE /bfc/credentials/{id}`.
 *
 * On this store `revoked_at` is the kill switch (the guard's active scope
 * checks it), so stamping it is the whole death — no expiry conflation. A
 * PENDING row (an unexchanged enrollment) is revocable too, and revoking
 * it consumes any still-pending claim code linked to it in the same
 * transaction: killing an enrollment kills the code that would complete
 * it. Idempotent on rows already dead — no second audit event for the
 * same death.
 */
final class RevokeCredential
{
    use ConsultsDeclaration;

    public function __construct(private readonly LifecycleEventRecorder $recorder) {}

    public function __invoke(string $id, ?AuditActor $actor = null): RevokeOutcome
    {
        /** @var RevokeOutcome */
        return DB::transaction(function () use ($id, $actor): RevokeOutcome {
            /** @var Credential|null $target */
            $target = Credential::query()->whereKey($id)->lockForUpdate()->first();

            if ($target === null) {
                return RevokeOutcome::NotFound;
            }

            // The matrix consults the subject the ROW declares — never
            // anything the caller supplies (SEC-V3-07).
            if (! $this->verbAllowed(CredentialVerb::Revoke, $target->subject())) {
                throw CredentialVerbRefused::byMatrix(CredentialVerb::Revoke);
            }

            if ($target->revoked_at !== null
                || ($target->expires_at !== null && ! $target->expires_at->isAfter(now()))) {
                return RevokeOutcome::AlreadyDead;
            }

            $now = now();

            $target->forceFill(['revoked_at' => $now])->save();

            OnboardingToken::query()
                ->where('durable_token_id', $id)
                ->where('durable_store', DurableStore::Credentials->value)
                ->whereNull('consumed_at')
                ->update(['consumed_at' => $now]);

            $this->recorder->record(
                event: LifecycleEventType::Revoked,
                credentialId: $id,
                actor: $actor,
                reason: AuditReason::OperatorRequest,
            );

            return RevokeOutcome::Revoked;
        });
    }
}
