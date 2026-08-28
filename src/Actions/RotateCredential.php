<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Actions;

use ArtisanBuild\BuiltForCloud\Actions\Concerns\ConsultsDeclaration;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\AuditReason;
use ArtisanBuild\BuiltForCloud\Contracts\AuthorizesRotationOverrides;
use ArtisanBuild\BuiltForCloud\Contracts\ConstrainsMintedCredentials;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\CredentialSummary;
use ArtisanBuild\BuiltForCloud\CredentialVerb;
use ArtisanBuild\BuiltForCloud\DeliveryShape;
use ArtisanBuild\BuiltForCloud\DurableStore;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialVerbRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\Exceptions\RotationCutoverIncomplete;
use ArtisanBuild\BuiltForCloud\Exceptions\RotationRefused;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\MintedSecret;
use ArtisanBuild\BuiltForCloud\MintResult;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\ReportedStatus;
use ArtisanBuild\BuiltForCloud\RotateOptions;
use ArtisanBuild\BuiltForCloud\RotationResult;
use ArtisanBuild\BuiltForCloud\Scope;
use Carbon\CarbonInterface;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Throwable;

/**
 * The rotate verb over the unified store (PRD 1.7, D6, SEC-5): BY ID — the
 * primary verb — consumed by both `bfc:credential:rotate --local` and
 * `POST /bfc/credentials/{id}/rotate`. One implementation; neither
 * transport can rotate anything the other cannot.
 *
 * The default preserves EXACTLY: the ability set, the subject binding
 * (subject_type / subject_ref / user_id), the decorative name, and the
 * remaining expiry of the row it replaces. Never widening, never lifetime
 * extension, silently — ANY provided change (narrowing included:
 * predictability beats cleverness; and "provided as none" counts — expiry
 * to null, abilities to empty) requires the explicit override flag. The
 * override is a SEPARATELY authorized operation: the declaration's
 * dedicated {@see AuthorizesRotationOverrides} hook must approve it —
 * fail closed, a declaration that has not opted in denies every override
 * — the result must fit the same mint ceilings
 * ({@see ConstrainsMintedCredentials} via the shared check), and the
 * audit rows carry the override reason code plus the delta.
 *
 * Make-before-break, in two phases whose failure modes are the contract
 * (D6 point 5):
 *
 * 1. ONE transaction mints the replacement, stamps `rotated_at` on the old
 *    row, and records the `issued` + `rotated` (old → new lineage) events.
 *    Any follow-up write failing rolls ALL of it back — no orphan
 *    credential, and a retry works (failure path A).
 * 2. A separate write retires the old row: its expiry becomes the grace
 *    end (one hour; NOW under `emergency`) unless an earlier expiry
 *    already bounds it. At grace end the old row dies by its own expiry —
 *    no reaper needed. If THIS write fails, the committed replacement
 *    stands and {@see RotationCutoverIncomplete} names the still-live old
 *    row (failure path B).
 *
 * Per kind (D6 point 6): `bearer`/`basic` mint a fresh secret, delivered
 * once through the sealed carrier; `asymmetric` issues a fresh enrollment
 * code against a new PENDING row — the keypair is the client's to generate,
 * both credentials stay listed and the old key verifies through grace (the
 * Phase-2 reel rebuild completes the client half); `hmac` refuses
 * explicitly — its pending→active cutover ships with the kind (D9), and
 * nothing falls through to bearer semantics.
 */
final class RotateCredential
{
    use ConsultsDeclaration;

    /**
     * The grace window (PRD 1.7): how long the superseded row stays
     * resolvable after a default rotation. The same hour the legacy
     * `api_tokens` rotation has always granted.
     */
    public const int GRACE_SECONDS = 3600;

    public function __construct(private readonly LifecycleEventRecorder $recorder) {}

    /**
     * Returns null when no row carries the id (the transports' 404); every
     * other failure is a typed refusal or the two-phase contract above.
     */
    public function __invoke(string $id, RotateOptions $options, ?AuditActor $actor = null): ?RotationResult
    {
        /** @var RotationResult|null $result */
        $result = DB::transaction(fn (): ?RotationResult => $this->mintReplacement($id, $options, $actor));

        if ($result === null) {
            return null;
        }

        try {
            $this->retire($result->supersededId, $options->emergency);
        } catch (Throwable $exception) {
            throw RotationCutoverIncomplete::retirementFailed(
                $result->supersededId,
                $result->mint->summary->id,
                $exception,
            );
        }

        return $result;
    }

    /**
     * The name path, a CLI convenience only (PRD 1.19): resolves the ONE
     * active credential of the name to its id, refusing whenever more than
     * one exists (D6 point 2 — never "which lifetime wins"). Rotation by id
     * remains the primary verb.
     */
    public function idForName(string $name): string
    {
        /** @var list<string> $ids */
        $ids = Credential::query()->where('name', $name)->active()->pluck('id')->all();

        if (count($ids) > 1) {
            throw RotationRefused::ambiguousName($name, count($ids));
        }

        if ($ids === []) {
            throw RotationRefused::unknownName($name);
        }

        return $ids[0];
    }

    /**
     * Phase 1, inside the caller's transaction: every refusal, the
     * replacement mint, the `rotated_at` stamp, and both audit events.
     */
    private function mintReplacement(string $id, RotateOptions $options, ?AuditActor $actor): ?RotationResult
    {
        /** @var Credential|null $source */
        $source = Credential::query()->whereKey($id)->lockForUpdate()->first();

        if ($source === null) {
            return null;
        }

        // The matrix consults the subject the ROW declares — never
        // anything the caller supplies (SEC-V3-07).
        if (! $this->verbAllowed(CredentialVerb::Rotate, $source->subject())) {
            throw CredentialVerbRefused::byMatrix(CredentialVerb::Rotate);
        }

        if ($source->status === CredentialStatus::Pending) {
            throw RotationRefused::sourcePending($id);
        }

        if ($source->revoked_at !== null) {
            throw RotationRefused::sourceDead($id, ReportedStatus::Revoked->value);
        }

        if ($source->expires_at !== null && ! $source->expires_at->isAfter(now())) {
            throw RotationRefused::sourceDead($id, ReportedStatus::Expired->value);
        }

        // A row already superseded by rotation never rotates AGAIN — a
        // second rotation of the SAME source would fork the lineage
        // (A→B and A→C), leaving supersession unable to say which
        // replacement is current. But when a lineage-verified LIVE
        // successor stands, re-invoking the verb performs the narrowly
        // scoped CUTOVER COMPLETION instead: retirement of the stamped
        // row only, nothing minted. That closes failure path B (and the
        // compromised-old-secret emergency on a graced row) under the
        // rotate verb's own authority — retiring what a rotation
        // superseded is part of the rotation the operator was authorized
        // for, and it is no revoke bypass: only a stamped row with a
        // live successor qualifies, and it is audited with its own
        // reason code. A stamped row whose successor is dead (or whose
        // lineage records none) still refuses.
        if ($source->rotated_at !== null) {
            return $this->completeCutover($source, $options, $actor);
        }

        if ($source->kind === CredentialKind::Hmac) {
            throw CredentialVerbRefused::kindNotRotatable($source->kind->value);
        }

        $override = $this->authorizeAnyOverride($source, $options);

        // An override changes exactly the dimensions it PROVIDED — where
        // "provided as none" is a real override (expiry to null, abilities
        // to empty); a dimension it left out is preserved like the default
        // path preserves it.
        $abilities = ($override && $options->abilitiesProvided) ? $options->abilities : $source->abilities;
        $expiresAt = ($override && $options->expiryProvided) ? $options->expiresAt : $source->expires_at;

        // An authorized override must still fit the mint ceilings: it can
        // never produce a credential a mint of that shape could not have
        // been authorized for. Checked on the replacement's EFFECTIVE
        // shape — inherited dimensions included — because the ceiling
        // bounds what gets created, not what got typed. Routine rotation
        // (exact preservation) deliberately skips this: preserving what
        // already exists is not a grant.
        if ($override) {
            $this->refuseWideningPastCeilings($source->subject(), $abilities, $expiresAt);
        }

        $reason = $override ? AuditReason::Override : ($options->emergency ? AuditReason::Emergency : AuditReason::Rotation);
        $note = $override ? $this->overrideNote($source, $options, $abilities, $expiresAt) : null;

        $result = $source->kind === CredentialKind::Asymmetric
            ? $this->replaceWithEnrollment($source, $options, $abilities, $expiresAt)
            : $this->replaceWithSecret($source, $abilities, $expiresAt);

        Credential::query()->whereKey($source->id)->update(['rotated_at' => now()]);

        $this->recorder->record(
            event: LifecycleEventType::Issued,
            credentialId: $result->summary->id,
            actor: $actor,
            credentialExpiresAt: $expiresAt,
            reason: $reason,
            note: $note,
        );

        $this->recorder->record(
            event: LifecycleEventType::Rotated,
            credentialId: $source->id,
            actor: $actor,
            reason: $reason,
            note: $note,
            supersededByCredentialId: $result->summary->id,
        );

        return new RotationResult($result, $source->id);
    }

    /**
     * The cutover-completion path (rework 3, Fix 3): the stamped source is
     * retired — by the caller's transaction here (the audit event) and the
     * shared phase-2 expiry-set that follows in __invoke — and the live
     * successor is reported as the standing replacement with NOTHING
     * minted and nothing to reveal. `emergency` keeps its meaning (the
     * old row dies NOW instead of at grace end), which is exactly the
     * compromised-old-secret case on an already-graced row. Override
     * options are meaningless here — nothing is minted for them to
     * change — and are refused rather than ignored.
     */
    private function completeCutover(Credential $source, RotateOptions $options, ?AuditActor $actor): RotationResult
    {
        $successorId = $this->successorOf($source->id);
        $successor = $successorId !== null
            ? Credential::query()->whereKey($successorId)->first()
            : null;

        if ($successor === null
            || $successor->revoked_at !== null
            || ($successor->expires_at !== null && ! $successor->expires_at->isAfter(now()))) {
            throw RotationRefused::alreadyRotated($source->id, $successorId);
        }

        if ($options->override || $options->requestsChange()) {
            throw InvalidCredentialInput::cutoverCompletionTakesNoOverrides();
        }

        $this->recorder->record(
            event: LifecycleEventType::Rotated,
            credentialId: $source->id,
            actor: $actor,
            reason: AuditReason::CutoverCompletion,
            supersededByCredentialId: $successor->id,
        );

        return new RotationResult(
            mint: new MintResult(
                summary: $this->summarize($successor),
                delivery: DeliveryShape::None,
            ),
            supersededId: $source->id,
            completedCutover: true,
        );
    }

    /**
     * The override discipline (D6 point 4). Returns whether an authorized
     * override applies. A provided change without the flag is refused; the
     * flag with nothing provided is refused; a flagged change is put to
     * the declaration's DEDICATED override hook
     * ({@see AuthorizesRotationOverrides}), which FAILS CLOSED: a
     * declaration that has not explicitly opted in denies every override.
     * Routine rotation authorization (the verb matrix's `rotate` answer,
     * already consulted) is unchanged by any of this.
     */
    private function authorizeAnyOverride(Credential $source, RotateOptions $options): bool
    {
        if (! $options->override) {
            if ($options->requestsChange()) {
                throw InvalidCredentialInput::rotationChangeRequiresOverride();
            }

            return false;
        }

        if (! $options->requestsChange()) {
            throw InvalidCredentialInput::rotationOverrideWithoutChanges();
        }

        $declaration = $this->declaration();

        if (! $declaration instanceof AuthorizesRotationOverrides
            || ! $declaration->authorizeRotationOverride($source->subject(), $options->overrideDelta(), $this->currentRequest())) {
            throw CredentialVerbRefused::overrideNotAuthorized();
        }

        return true;
    }

    /**
     * @param  list<string>|null  $abilities
     */
    private function replaceWithSecret(Credential $source, ?array $abilities, ?CarbonInterface $expiresAt): MintResult
    {
        $secret = new MintedSecret(
            (string) config('built-for-cloud.token_prefix').bin2hex(random_bytes(32)),
        );

        $replacement = Credential::query()->create([
            'kind' => $source->kind,
            'subject_type' => $source->subject_type,
            'subject_ref' => $source->subject_ref,
            'name' => $source->name,
            'abilities' => $abilities,
            'user_id' => $source->user_id,
            'expires_at' => $expiresAt,
            'secret_hash' => $secret->hash(),
            'status' => CredentialStatus::Active,
        ]);

        return new MintResult(
            summary: $this->summarize($replacement),
            delivery: $source->kind === CredentialKind::Basic ? DeliveryShape::BasicAuth : DeliveryShape::Bearer,
            secret: $secret,
            basicUsername: $source->kind === CredentialKind::Basic ? $replacement->id : null,
        );
    }

    /**
     * The asymmetric rotation (D6 point 6): a fresh PENDING row — no key
     * material of any kind; the customer generates the new keypair
     * client-side — delivered as a fresh enrollment code. The old
     * credential's public key keeps verifying through the grace window,
     * so both rows are listed side by side until cutover completes.
     *
     * @param  list<string>|null  $abilities
     */
    private function replaceWithEnrollment(
        Credential $source,
        RotateOptions $options,
        ?array $abilities,
        ?CarbonInterface $expiresAt,
    ): MintResult {
        $ttlSeconds = $options->codeTtlSeconds;

        if ($ttlSeconds === null
            || $ttlSeconds < MintCredential::CODE_TTL_MIN_SECONDS
            || $ttlSeconds > MintCredential::CODE_TTL_MAX_SECONDS) {
            throw InvalidCredentialInput::codeTtlOutOfBounds();
        }

        $replacement = Credential::query()->create([
            'kind' => CredentialKind::Asymmetric,
            'subject_type' => $source->subject_type,
            'subject_ref' => $source->subject_ref,
            'name' => $source->name,
            'abilities' => $abilities,
            'user_id' => $source->user_id,
            'expires_at' => $expiresAt,
            'status' => CredentialStatus::Pending,
        ]);

        do {
            $code = new MintedSecret(bin2hex(random_bytes(32)));
        } while (OnboardingToken::query()->where('token_hash', $code->hash())->exists());

        OnboardingToken::query()->create([
            'id' => (string) Str::uuid(),
            'email' => null,
            'scope' => Scope::Onboard->value,
            'token_hash' => $code->hash(),
            'durable_token_id' => $replacement->id,
            'durable_store' => DurableStore::Credentials,
            'expires_at' => now()->addSeconds($ttlSeconds),
        ]);

        return new MintResult(
            summary: $this->summarize($replacement),
            delivery: DeliveryShape::EnrollmentCode,
            secret: $code,
        );
    }

    /**
     * Phase 2 — the cutover: the old row's expiry becomes the grace end
     * (NOW under emergency), and at grace end the row dies by its own
     * expiry, no reaper needed. The guarded predicate is the never-extend
     * rule: a row already expiring EARLIER keeps its earlier death —
     * rotation never silently lengthens any credential's life.
     */
    private function retire(string $id, bool $emergency): void
    {
        $graceEnd = $emergency ? now() : now()->addSeconds(self::GRACE_SECONDS);

        Credential::query()
            ->whereKey($id)
            ->where(function ($query) use ($graceEnd): void {
                $query->whereNull('expires_at')->orWhere('expires_at', '>', $graceEnd);
            })
            ->update(['expires_at' => $graceEnd]);
    }

    /**
     * The bounded, secret-free delta the override's audit rows carry:
     * every dimension the override PROVIDED, from what, to what — a
     * provided dimension is named even when its value matches, because
     * the audit answers "what was authorized", not "what differed".
     *
     * @param  list<string>|null  $abilities
     */
    private function overrideNote(Credential $source, RotateOptions $options, ?array $abilities, ?CarbonInterface $expiresAt): string
    {
        $parts = [];

        if ($options->abilitiesProvided) {
            $parts[] = sprintf(
                'abilities %s -> %s',
                json_encode($source->abilities ?? []),
                json_encode($abilities ?? []),
            );
        }

        if ($options->expiryProvided) {
            $parts[] = sprintf(
                'expires_at %s -> %s',
                $source->expires_at?->toIso8601String() ?? 'null',
                $expiresAt?->toIso8601String() ?? 'null',
            );
        }

        return 'override: '.implode('; ', $parts);
    }

    /**
     * The most recent successor the audit lineage records for a rotated
     * row, so a refused re-rotation can point at the row to rotate
     * instead. Null only when the stamp exists without a lineage event
     * (a manual import) — the refusal still stands.
     */
    private function successorOf(string $id): ?string
    {
        $successor = CredentialAuditEvent::query()
            ->where('credential_id', $id)
            ->where('event', LifecycleEventType::Rotated->value)
            ->orderByDesc('occurred_at')
            ->value('superseded_by_credential_id');

        return is_string($successor) && $successor !== '' ? $successor : null;
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
