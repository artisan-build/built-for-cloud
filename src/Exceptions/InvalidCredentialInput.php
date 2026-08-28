<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Exceptions;

use ArtisanBuild\BuiltForCloud\MintOptions;
use InvalidArgumentException;

/**
 * Malformed input to a unified-store verb — distinct from
 * {@see CredentialVerbRefused}, which is an AUTHORITY answer. Thrown by
 * the shared input normalization ({@see MintOptions::fromInput()})
 * and the actions' own bounds checks, so both transports reject the same
 * junk with the SAME error: the CLI maps it to a failure exit, the HTTP
 * surface to a 422, each carrying this message verbatim. Never carries a
 * secret.
 */
final class InvalidCredentialInput extends InvalidArgumentException
{
    public static function unknownKind(string $kind): self
    {
        return new self(sprintf('Unknown credential kind "%s".', $kind));
    }

    public static function unknownSubjectType(string $subjectType): self
    {
        return new self(sprintf('Unknown subject type "%s".', $subjectType));
    }

    public static function missingSubjectRef(): self
    {
        return new self('A subject ref is required.');
    }

    public static function integrationNamespaceNotBound(): self
    {
        return new self(
            'This external subject already has version-gate history under a different integration namespace; '
            .'a namespace with no history for it cannot advance its gate or offboard it. '
            .'Send the event under the bound namespace, or use the direct offboard path.',
        );
    }

    public static function integrationSubjectMismatch(): self
    {
        return new self(
            'An integration-driven offboard targets the subject its gated external_subject binds to; '
            .'a different subject_type/subject_ref cannot be supplied. Omit the pair, or use the direct path without an integration event.',
        );
    }

    public static function nonIntegerCodeTtl(): self
    {
        return new self('The enrollment-code ttl must be a whole number of seconds — no units, no trailing text.');
    }

    public static function codeTtlOutOfBounds(): self
    {
        return new self(
            'Minting an asymmetric credential delivers an enrollment code, and the code\'s '
            .'ttl is required: pass a value between 60 and 604800 seconds.',
        );
    }

    public static function invitationTtlOutOfBounds(): self
    {
        return new self(
            'An invitation is a claim code and its ttl is required: pass ttl_seconds between 60 and '
            .'604800 seconds. The package never defaults an invitation lifetime.',
        );
    }

    public static function nonIntegerInvitationTtl(): self
    {
        return new self('The invitation ttl must be a whole number of seconds — no units, no trailing text.');
    }

    public static function malformedEmail(): self
    {
        return new self('The invitation email is not a valid address.');
    }

    public static function nonIntegerEntitlementVersion(): self
    {
        return new self('The entitlement version must be a whole number — no units, no trailing text.');
    }

    public static function entitlementVersionOutOfBounds(): self
    {
        return new self(
            'The entitlement version must be a whole number between 1 and 9007199254740992 (2^53). '
            .'Larger values are rejected, never truncated or saturated.',
        );
    }

    public static function invitationFieldTooLong(string $field, int $max): self
    {
        return new self(sprintf('The %s value is at most %d characters.', $field, $max));
    }

    public static function partialIntegrationEvent(): self
    {
        return new self(
            'Integration events carry integration_namespace, event_id, entitlement_version and '
            .'external_subject TOGETHER — provide all four, or none for a plain human-issued invitation.',
        );
    }

    public static function unparseableExpiry(): self
    {
        return new self('The credential expiry is not a parseable timestamp.');
    }

    public static function malformedAbilities(): self
    {
        return new self('Abilities must be a list of ability strings (or a comma-separated string of them).');
    }

    public static function tooManyAbilities(int $max): self
    {
        return new self(sprintf('A credential carries at most %d abilities.', $max));
    }

    public static function abilityTooLong(int $max): self
    {
        return new self(sprintf('An ability name is at most %d characters.', $max));
    }

    public static function nonBooleanFlag(string $flag): self
    {
        return new self(sprintf('The "%s" parameter must be a boolean.', $flag));
    }

    /**
     * Predictability beats cleverness (PRD 1.7): default rotation preserves
     * abilities and expiry EXACTLY, and any requested change — widening,
     * narrowing, or a different lifetime — is refused without the explicit
     * override flag. The package never decides that a narrowing was
     * probably fine.
     */
    public static function rotationChangeRequiresOverride(): self
    {
        return new self(
            'Rotation preserves the exact abilities and remaining expiry. To change either on the replacement, '
            .'pass the explicit override flag; without it any change — widening or narrowing — is refused.',
        );
    }

    public static function rotationOverrideWithoutChanges(): self
    {
        return new self(
            'The override flag was passed with nothing to override: supply the replacement abilities and/or expiry '
            .'the override changes.',
        );
    }

    public static function cutoverCompletionTakesNoOverrides(): self
    {
        return new self(
            'This credential was already superseded: re-invoking rotate completes the cutover by retiring it — '
            .'nothing is minted, so override options do not apply here.',
        );
    }

    /**
     * The activation verb's required confirmation (SEC-V3-01 rework):
     * activation binds to one exact delivery, so it takes the delivery
     * fingerprint the receiver quoted back — never just an id.
     */
    public static function activationRequiresDeliveryFingerprint(): self
    {
        return new self(
            'Activation requires the delivery fingerprint the receiver confirmed (it rides every signing-key '
            .'delivery), so the cutover binds to the exact delivery that was installed — an id alone cannot say '
            .'which delivery was confirmed.',
        );
    }
}
