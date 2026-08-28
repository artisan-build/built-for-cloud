<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Actions;

use ArtisanBuild\BuiltForCloud\Actions\Concerns\ConsultsDeclaration;
use ArtisanBuild\BuiltForCloud\Actions\Concerns\RetiresSupersededCredentials;
use ArtisanBuild\BuiltForCloud\ActivationResult;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\CredentialSummary;
use ArtisanBuild\BuiltForCloud\CredentialVerb;
use ArtisanBuild\BuiltForCloud\DurableStore;
use ArtisanBuild\BuiltForCloud\Exceptions\ActivationRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialVerbRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\Exceptions\RewrapInProgress;
use ArtisanBuild\BuiltForCloud\Exceptions\RotationCutoverIncomplete;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\ReportedStatus;
use Illuminate\Support\Facades\DB;
use Throwable;

/**
 * The activate verb (PRD 1.21, SEC-V3-01): the hmac kind's pending→active
 * SIGNING CUTOVER, and the only thing in the package that performs it.
 * ONE implementation consumed by both transports
 * (`bfc:credential:activate --local` and
 * `POST /bfc/credentials/{id}/activate`).
 *
 * Why a separate verb exists at all: the claim exchange is a bearer
 * capability — an inbox interceptor can redeem it — so exchange DELIVERS
 * and never activates. Activation is the operator-authorized transition
 * taken AFTER the receiver confirms installation out-of-band; its matrix
 * verb is its own (`activate`), so a declaration can allow rotation while
 * reserving the cutover.
 *
 * Activation confirms the EXACT delivered generation (SEC-V3-01 rework,
 * finding 1): the verb REQUIRES the delivery fingerprint the receiver
 * quoted back out-of-band, and refuses unless it matches the row's
 * CURRENT delivery. Without this binding, an interceptor could re-claim
 * (re-keying the pending row, same key id) AFTER the receiver confirmed
 * the earlier delivery, and the operator's stale confirmation would
 * activate the attacker's key — the forbidden exchange-flips-signing
 * semantic through a side door. With it, a re-key between confirmation
 * and activation changes the fingerprint and the stale activation
 * refuses; the operator re-confirms the delivery actually installed.
 *
 * What it refuses, identically on both transports:
 * - a missing delivery fingerprint (shared input refusal);
 * - a non-hmac kind (no other kind has this transition);
 * - a declaration whose matrix denies `activate` for the row's subject;
 * - any moment an APP_KEY rewrap is in progress (SEC-V3-08);
 * - a dead row (revoked / expired);
 * - a row already active — duplicate activation is REFUSED, not
 *   idempotent ({@see ActivationRefused::alreadyActive});
 * - an UNDELIVERED key (locked AC 3): neither revealed at mint nor
 *   exchanged — the receiver cannot have installed it;
 * - a STALE confirmation: a fingerprint that is not the row's current
 *   delivery ({@see ActivationRefused::staleDeliveryConfirmation}).
 *
 * What it does, in the rotate verb's own two-phase shape:
 * 1. ONE transaction verifies the confirmed fingerprint against the
 *    row's current delivery, flips pending→active (stamping
 *    `activated_at`), and consumes the linked claim code — activation is
 *    this kind's first observable use, the `first_use` burn point — all
 *    atomically, so once a generation activates, no further re-key of
 *    that code is possible (the code is dead and the row is no longer
 *    pending). Records the `activated` event (ids + the confirmed
 *    fingerprint, never values).
 * 2. When the activation completes a ROTATION cutover (the lineage
 *    records a predecessor this row superseded), a separate write
 *    retires that old key into its grace window: it keeps VERIFYING
 *    (active-or-grace, key id selecting) until grace end, then dies by
 *    its own expiry. If this write fails, the activation stands and
 *    {@see RotationCutoverIncomplete} names the still-live old row —
 *    re-invoking rotate on it performs the cutover completion.
 */
final class ActivateCredential
{
    use ConsultsDeclaration;
    use RetiresSupersededCredentials;

    public function __construct(
        private readonly LifecycleEventRecorder $recorder,
        private readonly HmacKeyring $keyring,
    ) {}

    /**
     * Returns null when no row carries the id (the transports' 404).
     * `$deliveryFingerprint` is the delivery the operator CONFIRMED —
     * required, and it must be the row's current one.
     */
    public function __invoke(string $id, ?string $deliveryFingerprint, ?AuditActor $actor = null): ?ActivationResult
    {
        // The shared input refusal, before anything is looked up: both
        // transports reject a missing confirmation identically.
        if ($deliveryFingerprint === null || trim($deliveryFingerprint) === '') {
            throw InvalidCredentialInput::activationRequiresDeliveryFingerprint();
        }

        /** @var array{CredentialSummary, string|null}|null $activated */
        $activated = DB::transaction(fn (): ?array => $this->cutOver($id, $deliveryFingerprint, $actor));

        if ($activated === null) {
            return null;
        }

        [$summary, $supersededId] = $activated;

        if ($supersededId === null) {
            return new ActivationResult($summary);
        }

        $graceEndsAt = now()->addSeconds(RotateCredential::GRACE_SECONDS);

        try {
            $this->retire($supersededId, false);
        } catch (Throwable $exception) {
            throw RotationCutoverIncomplete::activationRetirementFailed($supersededId, $summary->id, $exception);
        }

        return new ActivationResult($summary, $supersededId, $graceEndsAt);
    }

    /**
     * Phase 1, inside the caller's transaction: every refusal, the flip,
     * the code burn, the event, and the predecessor lookup.
     *
     * @return array{CredentialSummary, string|null}|null
     */
    private function cutOver(string $id, string $deliveryFingerprint, ?AuditActor $actor): ?array
    {
        /** @var Credential|null $credential */
        $credential = Credential::query()->whereKey($id)->lockForUpdate()->first();

        if ($credential === null) {
            return null;
        }

        if ($credential->kind !== CredentialKind::Hmac) {
            throw ActivationRefused::wrongKind($credential->kind->value);
        }

        // The matrix consults the subject the ROW declares — never
        // anything the caller supplies (SEC-V3-07).
        if (! $this->verbAllowed(CredentialVerb::Activate, $credential->subject())) {
            throw CredentialVerbRefused::byMatrix(CredentialVerb::Activate);
        }

        if ($this->keyring->cutoverInProgress()) {
            throw RewrapInProgress::refusing('activation');
        }

        if ($credential->revoked_at !== null) {
            throw ActivationRefused::dead($id, ReportedStatus::Revoked->value);
        }

        if ($credential->expires_at !== null && ! $credential->expires_at->isAfter(now())) {
            throw ActivationRefused::dead($id, ReportedStatus::Expired->value);
        }

        if ($credential->status === CredentialStatus::Active) {
            throw ActivationRefused::alreadyActive($id);
        }

        if ($credential->delivered_at === null) {
            throw ActivationRefused::notDelivered($id);
        }

        // The generation binding (SEC-V3-01 rework): the confirmation
        // must name the row's CURRENT delivery. A redelivery after the
        // confirmation changed the fingerprint — the stale confirmation
        // refuses, and the attacker's re-keyed material never activates
        // on the strength of a confirmation of something else.
        if ($credential->delivery_fingerprint === null
            || ! hash_equals($credential->delivery_fingerprint, $deliveryFingerprint)) {
            throw ActivationRefused::staleDeliveryConfirmation($id);
        }

        // Activation is the hmac kind's first observable use: the
        // `first_use` burn point. The linked claim code (if any, and not
        // already burned by an `at_exchange` declaration) dies here, so
        // a link left in an inbox cannot re-deliver a LIVE key.
        $codeId = OnboardingToken::query()
            ->where('durable_token_id', $credential->id)
            ->where('durable_store', DurableStore::Credentials->value)
            ->whereNull('consumed_at')
            ->value('id');

        if (is_string($codeId)) {
            OnboardingToken::query()->whereKey($codeId)->update(['consumed_at' => now()]);
        }

        Credential::query()->whereKey($credential->id)->update([
            'status' => CredentialStatus::Active->value,
            'activated_at' => now(),
        ]);

        $this->recorder->record(
            event: LifecycleEventType::Activated,
            credentialId: $credential->id,
            codeId: is_string($codeId) ? $codeId : null,
            actor: $actor,
            note: 'confirmed delivery generation '.$credential->delivered_generation.' ('.$deliveryFingerprint.')',
        );

        return [$this->summarize($credential->refresh()), $this->livePredecessorOf($credential->id)];
    }

    /**
     * The rotation predecessor this activation cuts over from: the row
     * whose `rotated` lineage event names this credential as successor —
     * and only while that row is still live (an already-dead predecessor
     * leaves nothing to retire). Null for a first mint: there is no old
     * key, and activation retires nothing.
     */
    private function livePredecessorOf(string $id): ?string
    {
        $predecessorId = CredentialAuditEvent::query()
            ->where('superseded_by_credential_id', $id)
            ->where('event', LifecycleEventType::Rotated->value)
            ->orderByDesc('occurred_at')
            ->value('credential_id');

        if (! is_string($predecessorId) || $predecessorId === '') {
            return null;
        }

        $live = Credential::query()
            ->whereKey($predecessorId)
            ->whereNull('revoked_at')
            ->where(function ($query): void {
                $query->whereNull('expires_at')->orWhere('expires_at', '>', now());
            })
            ->exists();

        return $live ? $predecessorId : null;
    }

    private function summarize(Credential $credential): CredentialSummary
    {
        return CredentialSummary::fromCredential(
            $credential,
            $this->declaredCadence(),
            $this->declaredUnsupportedFields(),
        );
    }
}
