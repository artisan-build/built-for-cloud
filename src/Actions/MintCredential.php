<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Actions;

use ArtisanBuild\BuiltForCloud\Actions\Concerns\ConsultsDeclaration;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\Contracts\ConstrainsMintedCredentials;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\CredentialSummary;
use ArtisanBuild\BuiltForCloud\CredentialVerb;
use ArtisanBuild\BuiltForCloud\DeliveryShape;
use ArtisanBuild\BuiltForCloud\DurableStore;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialVerbRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\MintedSecret;
use ArtisanBuild\BuiltForCloud\MintOptions;
use ArtisanBuild\BuiltForCloud\MintResult;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\Subject;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * The mint verb (PRD 1.0 + 1.6): `mint(Subject, MintOptions): MintResult` —
 * a subject, never an id, because you cannot mint by id a row that does not
 * exist. ONE implementation consumed by BOTH transports (`bfc:credential:mint
 * --local` and `POST /bfc/credentials`); neither transport can mint anything
 * the other cannot.
 *
 * What it refuses, identically on both transports:
 * - a declaration whose verb matrix denies `issue` for the subject;
 * - ability or lifetime WIDENING past a declared ceiling
 *   ({@see ConstrainsMintedCredentials});
 * - options that set a declared-unsupported summary field.
 *
 * The secret is born inside a sealed {@see MintedSecret} and leaves it once,
 * at the transport boundary. The `issued` audit event rides the mint's own
 * transaction (SEC-V3-09).
 */
final class MintCredential
{
    use ConsultsDeclaration;

    /**
     * The claim-code primitive's package-enforced TTL bounds (PRD 1.1),
     * applying to the enrollment CODE only — never to the credential.
     * Public because rotation's asymmetric path delivers the same
     * enrollment code under the same bounds ({@see RotateCredential}).
     */
    public const int CODE_TTL_MIN_SECONDS = 60;

    public const int CODE_TTL_MAX_SECONDS = 604800;

    public function __construct(private readonly LifecycleEventRecorder $recorder) {}

    public function __invoke(Subject $subject, MintOptions $options, ?AuditActor $actor = null): MintResult
    {
        if (! $this->verbAllowed(CredentialVerb::Issue, $subject)) {
            throw CredentialVerbRefused::byMatrix(CredentialVerb::Issue);
        }

        $this->refuseWidening($subject, $options);
        $this->refuseUnsupportedOptions($options);

        return match ($options->kind) {
            CredentialKind::Bearer,
            CredentialKind::Basic => $this->mintSecretBearing($subject, $options, $actor),
            CredentialKind::Asymmetric => $this->mintEnrollment($subject, $options, $actor),
            CredentialKind::Hmac => $this->mintSigningKey($subject, $options, $actor),
        };
    }

    /**
     * The widening refusal (locked AC 2), shared with the rotation
     * override's ceiling check ({@see ConsultsDeclaration}).
     */
    private function refuseWidening(Subject $subject, MintOptions $options): void
    {
        $this->refuseWideningPastCeilings($subject, $options->abilities, $options->expiresAt);
    }

    private function refuseUnsupportedOptions(MintOptions $options): void
    {
        $unsupported = $this->declaredUnsupportedFields();

        if (in_array('name', $unsupported, true) && $options->name !== null) {
            throw CredentialVerbRefused::unsupportedField('name');
        }

        if (in_array('abilities', $unsupported, true) && $options->abilities !== null) {
            throw CredentialVerbRefused::unsupportedField('abilities');
        }

        if (in_array('expires_at', $unsupported, true) && $options->expiresAt !== null) {
            throw CredentialVerbRefused::unsupportedField('expires_at');
        }
    }

    /**
     * `bearer` and `basic`: a secret is generated, its sha256 is what the
     * store keeps, and the plaintext exists only inside the carrier.
     */
    private function mintSecretBearing(Subject $subject, MintOptions $options, ?AuditActor $actor): MintResult
    {
        /** @var MintResult */
        return DB::transaction(function () use ($subject, $options, $actor): MintResult {
            $secret = new MintedSecret(
                (string) config('built-for-cloud.token_prefix').bin2hex(random_bytes(32)),
            );

            $credential = Credential::query()->create([
                'kind' => $options->kind,
                'subject_type' => $subject->type,
                'subject_ref' => $subject->ref,
                'name' => $options->name,
                'abilities' => $options->abilities,
                'user_id' => $options->userId,
                'expires_at' => $options->expiresAt,
                'secret_hash' => $secret->hash(),
                'status' => CredentialStatus::Active,
            ]);

            $this->recorder->record(
                event: LifecycleEventType::Issued,
                credentialId: $credential->id,
                actor: $actor,
                credentialExpiresAt: $options->expiresAt,
            );

            return new MintResult(
                summary: $this->summarize($credential),
                delivery: $options->kind === CredentialKind::Basic ? DeliveryShape::BasicAuth : DeliveryShape::Bearer,
                secret: $secret,
                // The auth.json username half: presentation-only, grants
                // nothing; the row id, so support can name the row.
                basicUsername: $options->kind === CredentialKind::Basic ? $credential->id : null,
            );
        });
    }

    /**
     * `asymmetric`: the minimal enrollment flow (PRD 1.6). A PENDING row is
     * created — public key and secret both absent, because the client will
     * generate its own keypair and the private half never exists server-side
     * — and the delivery is a claim-primitive code linked to it. The Phase 2
     * reel rebuild teaches exchange to complete the enrollment (register
     * the client-generated public key against the pending row); until then
     * the code is issued and revocable but completes no enrollment.
     */
    private function mintEnrollment(Subject $subject, MintOptions $options, ?AuditActor $actor): MintResult
    {
        $ttlSeconds = $options->codeTtlSeconds;

        // Input bounds, enforced in the ACTION so both transports reject
        // identically (Fix 4): the CLI maps this to a failure exit, HTTP
        // to a 422.
        if ($ttlSeconds === null || $ttlSeconds < self::CODE_TTL_MIN_SECONDS || $ttlSeconds > self::CODE_TTL_MAX_SECONDS) {
            throw InvalidCredentialInput::codeTtlOutOfBounds();
        }

        /** @var MintResult */
        return DB::transaction(function () use ($subject, $options, $actor, $ttlSeconds): MintResult {
            $credential = Credential::query()->create([
                'kind' => CredentialKind::Asymmetric,
                'subject_type' => $subject->type,
                'subject_ref' => $subject->ref,
                'name' => $options->name,
                'abilities' => $options->abilities,
                'user_id' => $options->userId,
                'expires_at' => $options->expiresAt,
                'status' => CredentialStatus::Pending,
            ]);

            do {
                $code = new MintedSecret(bin2hex(random_bytes(32)));
            } while (OnboardingToken::query()->where('token_hash', $code->hash())->exists());

            $codeRow = OnboardingToken::query()->create([
                'id' => (string) Str::uuid(),
                'email' => null,
                // `onboard`, not `consume`: were this code presented to the
                // legacy exchange today, the durable it would mint carries
                // an ability that grants nothing on any gate.
                'scope' => Scope::Onboard->value,
                'token_hash' => $code->hash(),
                'durable_token_id' => $credential->id,
                // The linkage names its store: the pending row lives in the
                // unified store whatever the declaration currently targets.
                'durable_store' => DurableStore::Credentials,
                'expires_at' => now()->addSeconds($ttlSeconds),
            ]);

            $this->recorder->record(
                event: LifecycleEventType::Issued,
                credentialId: $credential->id,
                codeId: $codeRow->id,
                actor: $actor,
                codeTtlSeconds: $ttlSeconds,
                credentialExpiresAt: $options->expiresAt,
            );

            return new MintResult(
                summary: $this->summarize($credential),
                delivery: DeliveryShape::EnrollmentCode,
                secret: $code,
            );
        });
    }

    /**
     * `hmac` (PRD 1.21, D9): a per-subject symmetric signing key, born
     * PENDING — a pending key signs nothing and verifies nothing until the
     * SEPARATE activation verb cuts it over (SEC-V3-01). The key is
     * encrypted at rest through the keyring, key-version stamped (D9.1,
     * SEC-V3-08).
     *
     * Delivery is chosen by `code_ttl_seconds`, the same discriminator the
     * claim primitive already is on the asymmetric kind: ABSENT, the key
     * is revealed once in this result — the operator-controlled
     * counterparty path (D7) — and the mint IS the delivery
     * (`delivered_at` now, `delivered` event). PRESENT, the standard path
     * to an outside counterparty: a claim code (PR3 primitive) whose
     * exchange delivers the pending key exactly once, audits the
     * delivery, and changes NOTHING about signing state.
     */
    private function mintSigningKey(Subject $subject, MintOptions $options, ?AuditActor $actor): MintResult
    {
        $ttlSeconds = $options->codeTtlSeconds;

        if ($ttlSeconds !== null && ($ttlSeconds < self::CODE_TTL_MIN_SECONDS || $ttlSeconds > self::CODE_TTL_MAX_SECONDS)) {
            throw InvalidCredentialInput::codeTtlOutOfBounds();
        }

        /** @var MintResult */
        return DB::transaction(function () use ($subject, $options, $actor, $ttlSeconds): MintResult {
            $signingKey = bin2hex(random_bytes(32));
            $encrypted = app(HmacKeyring::class)->encrypt($signingKey);

            $credential = new Credential;
            $credential->forceFill([
                'kind' => CredentialKind::Hmac,
                'subject_type' => $subject->type,
                'subject_ref' => $subject->ref,
                'name' => $options->name,
                'abilities' => $options->abilities,
                'user_id' => $options->userId,
                'expires_at' => $options->expiresAt,
                'status' => CredentialStatus::Pending,
                'secret_ciphertext' => $encrypted->ciphertext,
                'secret_key_version' => $encrypted->keyVersion,
            ])->save();

            if ($ttlSeconds === null) {
                // This result IS the delivery (reveal-once, D7).
                Credential::query()->whereKey($credential->id)->update(['delivered_at' => now()]);

                $this->recorder->record(
                    event: LifecycleEventType::Issued,
                    credentialId: $credential->id,
                    actor: $actor,
                    credentialExpiresAt: $options->expiresAt,
                );

                $this->recorder->record(
                    event: LifecycleEventType::Delivered,
                    credentialId: $credential->id,
                    actor: $actor,
                );

                return new MintResult(
                    summary: $this->summarize($credential->refresh()),
                    delivery: DeliveryShape::SigningKey,
                    secret: new MintedSecret($signingKey),
                );
            }

            do {
                $code = new MintedSecret(bin2hex(random_bytes(32)));
            } while (OnboardingToken::query()->where('token_hash', $code->hash())->exists());

            $codeRow = OnboardingToken::query()->create([
                'id' => (string) Str::uuid(),
                'email' => null,
                'scope' => Scope::Onboard->value,
                'token_hash' => $code->hash(),
                'durable_token_id' => $credential->id,
                'durable_store' => DurableStore::Credentials,
                'expires_at' => now()->addSeconds($ttlSeconds),
            ]);

            $this->recorder->record(
                event: LifecycleEventType::Issued,
                credentialId: $credential->id,
                codeId: $codeRow->id,
                actor: $actor,
                codeTtlSeconds: $ttlSeconds,
                credentialExpiresAt: $options->expiresAt,
            );

            return new MintResult(
                summary: $this->summarize($credential),
                delivery: DeliveryShape::SigningKeyCode,
                secret: $code,
            );
        });
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
