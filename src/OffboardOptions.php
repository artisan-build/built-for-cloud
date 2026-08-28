<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;

/**
 * What a caller chooses when offboarding a subject through the
 * two-transport verb (PRD 1.15, SEC-V3-04). The four integration-event
 * fields are all-or-none exactly as on the invite verb (SEC-V3-05) — a
 * direct operator offboard carries none, an integration-driven offboard
 * carries every one and rides the SAME version gate tables (PRD 1.13's),
 * so a replayed or older offboard event is transactionally ignored.
 *
 * The subject pair is REQUIRED on the direct path and OPTIONAL on the
 * integration path (rework Fix 4): an integration-driven offboard's
 * target is DERIVED server-side from the gated (namespace,
 * external_subject) identity — the exact binding the invite verb uses —
 * never taken from an independent caller-supplied ref, so the version
 * gate can never be checked against one identity while a different
 * victim is contained. A supplied subject that does not match the
 * derived one is refused ({@see OffboardSubject}).
 *
 * Both transports construct this through {@see fromInput()}, the ONE
 * normalization: junk is rejected with the same
 * {@see InvalidCredentialInput} on the CLI and over HTTP.
 */
final readonly class OffboardOptions
{
    public function __construct(
        public ?SubjectType $subjectType,
        public ?string $subjectRef,
        public ?string $integrationNamespace = null,
        public ?string $eventId = null,
        public ?int $entitlementVersion = null,
        public ?string $externalSubject = null,
    ) {}

    /**
     * @param  array<string, mixed>  $input
     */
    public static function fromInput(array $input): self
    {
        $integrationNamespace = self::boundedString($input['integration_namespace'] ?? null, 'integration_namespace');
        $eventId = self::boundedString($input['event_id'] ?? null, 'event_id');
        $entitlementVersion = self::wholeNumberFrom($input['entitlement_version'] ?? null);
        $externalSubject = self::boundedString($input['external_subject'] ?? null, 'external_subject');

        $eventComplete = $integrationNamespace !== null
            && $eventId !== null
            && $entitlementVersion !== null
            && $externalSubject !== null;

        $subjectType = $input['subject_type'] ?? null;
        $parsedType = null;

        if (is_string($subjectType) && $subjectType !== '') {
            $parsedType = SubjectType::tryFrom($subjectType);

            if ($parsedType === null) {
                throw InvalidCredentialInput::unknownSubjectType($subjectType);
            }
        }

        $subjectRef = $input['subject_ref'] ?? null;
        $parsedRef = null;

        if (is_string($subjectRef) && $subjectRef !== '') {
            if (strlen($subjectRef) > InvitationOptions::MAX_FIELD_LENGTH) {
                throw InvalidCredentialInput::invitationFieldTooLong('subject_ref', InvitationOptions::MAX_FIELD_LENGTH);
            }

            $parsedRef = $subjectRef;
        }

        // The direct path names its target explicitly; the integration
        // path derives it from the gated identity, so the pair may be
        // omitted there (and is verified against the derivation when
        // supplied — see the action).
        if (! $eventComplete) {
            if ($parsedType === null) {
                throw InvalidCredentialInput::unknownSubjectType(is_string($subjectType) ? $subjectType : '');
            }

            if ($parsedRef === null) {
                throw InvalidCredentialInput::missingSubjectRef();
            }
        }

        return new self(
            subjectType: $parsedType,
            subjectRef: $parsedRef,
            integrationNamespace: $integrationNamespace,
            eventId: $eventId,
            entitlementVersion: $entitlementVersion,
            externalSubject: $externalSubject,
        );
    }

    public function carriesIntegrationEvent(): bool
    {
        return $this->integrationNamespace !== null
            || $this->eventId !== null
            || $this->entitlementVersion !== null
            || $this->externalSubject !== null;
    }

    public function integrationEventComplete(): bool
    {
        return $this->integrationNamespace !== null
            && $this->eventId !== null
            && $this->entitlementVersion !== null
            && $this->externalSubject !== null;
    }

    private static function boundedString(mixed $value, string $field): ?string
    {
        if (! is_string($value) || $value === '') {
            return null;
        }

        if (strlen($value) > InvitationOptions::MAX_FIELD_LENGTH) {
            throw InvalidCredentialInput::invitationFieldTooLong($field, InvitationOptions::MAX_FIELD_LENGTH);
        }

        return $value;
    }

    /**
     * A whole number only — junk is junk on both transports; a negative
     * parses so both converge on the same BOUNDS error in the action.
     */
    private static function wholeNumberFrom(mixed $value): ?int
    {
        if ($value === null || $value === '') {
            return null;
        }

        if (is_int($value)) {
            return $value;
        }

        if (is_string($value) && preg_match('/^-?\d+$/', $value) === 1) {
            return (int) $value;
        }

        throw InvalidCredentialInput::nonIntegerEntitlementVersion();
    }
}
