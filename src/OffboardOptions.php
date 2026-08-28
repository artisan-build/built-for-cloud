<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;

/**
 * What a caller chooses when offboarding a subject through the
 * two-transport verb (PRD 1.15, SEC-V3-04). The subject pair is
 * required; the four integration-event fields are all-or-none exactly as
 * on the invite verb (SEC-V3-05) — a direct operator offboard carries
 * none, an integration-driven offboard carries every one and rides the
 * SAME version gate tables (PRD 1.13's), so a replayed or older offboard
 * event is transactionally ignored.
 *
 * Both transports construct this through {@see fromInput()}, the ONE
 * normalization: junk is rejected with the same
 * {@see InvalidCredentialInput} on the CLI and over HTTP.
 */
final readonly class OffboardOptions
{
    public function __construct(
        public SubjectType $subjectType,
        public string $subjectRef,
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
        $subjectType = $input['subject_type'] ?? null;
        $parsedType = is_string($subjectType) ? SubjectType::tryFrom($subjectType) : null;

        if ($parsedType === null) {
            throw InvalidCredentialInput::unknownSubjectType(is_string($subjectType) ? $subjectType : '');
        }

        $subjectRef = $input['subject_ref'] ?? null;

        if (! is_string($subjectRef) || $subjectRef === '') {
            throw InvalidCredentialInput::missingSubjectRef();
        }

        if (strlen($subjectRef) > InvitationOptions::MAX_FIELD_LENGTH) {
            throw InvalidCredentialInput::invitationFieldTooLong('subject_ref', InvitationOptions::MAX_FIELD_LENGTH);
        }

        return new self(
            subjectType: $parsedType,
            subjectRef: $subjectRef,
            integrationNamespace: self::boundedString($input['integration_namespace'] ?? null, 'integration_namespace'),
            eventId: self::boundedString($input['event_id'] ?? null, 'event_id'),
            entitlementVersion: self::wholeNumberFrom($input['entitlement_version'] ?? null),
            externalSubject: self::boundedString($input['external_subject'] ?? null, 'external_subject'),
        );
    }

    public function subject(): Subject
    {
        return new Subject($this->subjectType, $this->subjectRef);
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
