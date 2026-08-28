<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Actions;

use ArtisanBuild\BuiltForCloud\Actions\Concerns\ConsultsDeclaration;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\AuditReason;
use ArtisanBuild\BuiltForCloud\Credential;
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
 * extension, silently — ANY requested change (narrowing included:
 * predictability beats cleverness) requires the explicit override flag,
 * which is authorized through the verb matrix as its own consultation with
 * the override visible in the request context
 * ({@see OVERRIDE_CONTEXT_ATTRIBUTE}) and audited with its own reason code
 * plus the delta.
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
     * The request attribute carrying the override delta during the
     * override's OWN matrix consultation (D6 point 4): the declaration's
     * `authorizeVerb(Rotate, …)` hook sees this attribute set — an
     * `array{abilities: list<string>|null, expires_at: string|null}` of
     * what the override requests — exactly when it is being asked about an
     * override rather than a routine rotation. The attribute exists only
     * for the duration of that consultation.
     */
    public const string OVERRIDE_CONTEXT_ATTRIBUTE = 'bfc.rotation_override';

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

        if ($source->kind === CredentialKind::Hmac) {
            throw CredentialVerbRefused::kindNotRotatable($source->kind->value);
        }

        $override = $this->authorizeAnyOverride($source, $options);

        // An override changes exactly the dimensions it names; a dimension
        // it leaves out is preserved like the default path preserves it.
        $abilities = ($override && $options->abilities !== null) ? $options->abilities : $source->abilities;
        $expiresAt = ($override && $options->expiresAt !== null) ? $options->expiresAt : $source->expires_at;
        $reason = $override ? AuditReason::Override : ($options->emergency ? AuditReason::Emergency : AuditReason::Rotation);
        $note = $override ? $this->overrideDelta($source, $abilities, $expiresAt) : null;

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
     * The override discipline (D6 point 4). Returns whether an authorized
     * override applies. A change without the flag is refused; the flag
     * without a change is refused; a flagged change is put to the matrix as
     * its OWN consultation, with the delta visible in the request context.
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

        $request = $this->currentRequest();

        $request->attributes->set(self::OVERRIDE_CONTEXT_ATTRIBUTE, [
            'abilities' => $options->abilities,
            'expires_at' => $options->expiresAt?->toIso8601String(),
        ]);

        try {
            if (! $this->verbAllowed(CredentialVerb::Rotate, $source->subject())) {
                throw CredentialVerbRefused::overrideByMatrix();
            }
        } finally {
            $request->attributes->remove(self::OVERRIDE_CONTEXT_ATTRIBUTE);
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
     * which dimensions changed, from what, to what.
     *
     * @param  list<string>|null  $abilities
     */
    private function overrideDelta(Credential $source, ?array $abilities, ?CarbonInterface $expiresAt): string
    {
        $parts = [];

        if ($abilities !== $source->abilities) {
            $parts[] = sprintf(
                'abilities %s -> %s',
                json_encode($source->abilities ?? []),
                json_encode($abilities ?? []),
            );
        }

        if (($expiresAt?->toIso8601String()) !== ($source->expires_at?->toIso8601String())) {
            $parts[] = sprintf(
                'expires_at %s -> %s',
                $source->expires_at?->toIso8601String() ?? 'null',
                $expiresAt?->toIso8601String() ?? 'null',
            );
        }

        return 'override: '.($parts === [] ? 'restated current values' : implode('; ', $parts));
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
