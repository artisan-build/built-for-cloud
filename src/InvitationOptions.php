<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;

/**
 * What a caller chooses when issuing an invitation through the
 * two-transport verb (PRD 1.13, SEC-V3-05).
 *
 * `ttlSeconds` is REQUIRED by the action (60s–7d, PRD 1.1): the invitation
 * is a claim code and never defaults its lifetime. `email` is optional —
 * an unaddressed invitation is an OPEN code. `role` is stored and never
 * interpreted; the accept hook is where an app projects it.
 *
 * The four integration-event fields are all-or-none, enforced by the
 * action: a plain human-issued invite carries none of them; a
 * machine-issued event carries the namespace, the stable event id, the
 * monotonic entitlement version AND the external subject the version gate
 * keys on.
 *
 * Both transports construct this through {@see fromInput()}, the ONE
 * normalization: junk is rejected with the same
 * {@see InvalidCredentialInput} on the CLI and over HTTP.
 */
final readonly class InvitationOptions
{
    public function __construct(
        public ?string $email = null,
        public ?int $ttlSeconds = null,
        public ?string $invitedBy = null,
        public ?string $role = null,
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
        return new self(
            email: self::emailFrom($input['email'] ?? null),
            ttlSeconds: self::wholeNumberFrom($input['ttl_seconds'] ?? null, InvalidCredentialInput::nonIntegerInvitationTtl()),
            invitedBy: self::optionalString($input['invited_by'] ?? null),
            role: self::optionalString($input['role'] ?? null),
            integrationNamespace: self::optionalString($input['integration_namespace'] ?? null),
            eventId: self::optionalString($input['event_id'] ?? null),
            entitlementVersion: self::wholeNumberFrom($input['entitlement_version'] ?? null, InvalidCredentialInput::nonIntegerEntitlementVersion()),
            externalSubject: self::optionalString($input['external_subject'] ?? null),
        );
    }

    /**
     * Whether ANY integration-event field was provided; the action refuses
     * a partial group ({@see integrationEventComplete}).
     */
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

    private static function optionalString(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }

    private static function emailFrom(mixed $email): ?string
    {
        if ($email === null || $email === '') {
            return null;
        }

        if (! is_string($email) || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            throw InvalidCredentialInput::malformedEmail();
        }

        return $email;
    }

    /**
     * A whole number only — `"60junk"` is junk, never 60. A negative whole
     * number parses so both transports converge on the same BOUNDS error
     * in the action rather than a differing "not an integer" rejection.
     */
    private static function wholeNumberFrom(mixed $value, InvalidCredentialInput $onJunk): ?int
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

        throw $onJunk;
    }
}
