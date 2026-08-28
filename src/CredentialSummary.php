<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Carbon\CarbonInterface;

/**
 * The unified store's listing row (PRD 1.5 + 1.6, D3): metadata only, never
 * a secret and never a hash.
 *
 * The `unsupported` list is the declared-unsupported discrimination
 * (FLT-R5): a field named there is one this app's DECLARATION says the
 * store structurally cannot express — reel's rows have no name, no
 * abilities, no last_used_at, no credential expiry — and it is serialized
 * as null AND listed, so a consumer can tell "absent but supported" (null,
 * not listed) from "unknowable here" (null, listed) without guessing.
 */
final readonly class CredentialSummary
{
    /**
     * The summary fields a declaration may mark unsupported. Structural
     * fields (id, kind, subject, status, timestamps of record) are always
     * supported — a store that cannot say what a row IS has no listing.
     */
    public const array DECLARABLE_FIELDS = ['name', 'abilities', 'last_used_at', 'expires_at'];

    /**
     * @param  list<string>|null  $abilities
     * @param  list<string>  $unsupported
     */
    public function __construct(
        public string $id,
        public CredentialKind $kind,
        public SubjectType $subjectType,
        public string $subjectRef,
        public ?string $name,
        public ?array $abilities,
        public string $status,
        public ?CarbonInterface $createdAt,
        public ?CarbonInterface $lastUsedAt,
        public ?CarbonInterface $expiresAt,
        public ?CarbonInterface $revokedAt,
        public ?int $presentationCadenceSeconds,
        public array $unsupported = [],
        public ?CarbonInterface $rotatedAt = null,
    ) {}

    /**
     * @param  list<string>  $unsupported
     */
    public static function fromCredential(Credential $credential, ?int $presentationCadenceSeconds, array $unsupported = []): self
    {
        $unsupported = array_values(array_intersect($unsupported, self::DECLARABLE_FIELDS));

        return new self(
            id: $credential->id,
            kind: $credential->kind,
            subjectType: $credential->subject_type,
            subjectRef: $credential->subject_ref,
            name: in_array('name', $unsupported, true) ? null : $credential->name,
            abilities: in_array('abilities', $unsupported, true) ? null : $credential->abilities,
            status: self::statusOf($credential),
            createdAt: $credential->created_at,
            lastUsedAt: in_array('last_used_at', $unsupported, true) ? null : $credential->last_used_at,
            expiresAt: in_array('expires_at', $unsupported, true) ? null : $credential->expires_at,
            revokedAt: $credential->revoked_at,
            presentationCadenceSeconds: $presentationCadenceSeconds,
            unsupported: $unsupported,
            rotatedAt: $credential->rotated_at,
        );
    }

    /**
     * The computed status, `revoked` asked first because revocation is the
     * deliberate act; `pending` is a real lifecycle state on this store
     * (an unexchanged enrollment), not a failure. `unknown` stays reserved
     * in the vocabulary for rows that structurally cannot carry a signal —
     * nothing on this store produces it yet (see {@see ReportedStatus}).
     */
    private static function statusOf(Credential $credential): string
    {
        if ($credential->revoked_at !== null) {
            return ReportedStatus::Revoked->value;
        }

        if ($credential->expires_at !== null && ! $credential->expires_at->isAfter(now())) {
            return ReportedStatus::Expired->value;
        }

        if ($credential->status === CredentialStatus::Pending) {
            return CredentialStatus::Pending->value;
        }

        return ReportedStatus::Active->value;
    }

    /**
     * The ONE serialization both transports emit — the CLI's `--json` rows
     * and the HTTP listing are this array, byte-identical per row, which is
     * what makes transport parity assertable rather than aspirational.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'kind' => $this->kind->value,
            'subject_type' => $this->subjectType->value,
            'subject_ref' => $this->subjectRef,
            'name' => $this->name,
            'abilities' => $this->abilities,
            'status' => $this->status,
            'created_at' => $this->createdAt?->toIso8601String(),
            'last_used_at' => $this->lastUsedAt?->toIso8601String(),
            'expires_at' => $this->expiresAt?->toIso8601String(),
            'revoked_at' => $this->revokedAt?->toIso8601String(),
            // Rotation provenance (PRD 1.7): non-null names a row superseded
            // by rotation and living out its grace window — visible so the
            // listing can show old-in-grace beside new-active.
            'rotated_at' => $this->rotatedAt?->toIso8601String(),
            'presentation_cadence_seconds' => $this->presentationCadenceSeconds,
            'unsupported' => $this->unsupported,
        ];
    }
}
