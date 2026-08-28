<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Exceptions;

use ArtisanBuild\BuiltForCloud\CredentialVerb;
use RuntimeException;

/**
 * A unified-store verb was refused by the declaration — the matrix denied
 * it, or the mint would widen past a declared ceiling. Thrown by the ACTION
 * classes so both transports refuse identically: the CLI maps it to a
 * failure exit, the HTTP surface to a 403. The message is written for the
 * caller and never carries a secret.
 */
final class CredentialVerbRefused extends RuntimeException
{
    public static function byMatrix(CredentialVerb $verb): self
    {
        return new self(sprintf('The declaration denies the %s verb for this subject.', $verb->value));
    }

    public static function abilityWidening(string $ability): self
    {
        return new self(sprintf(
            'The declaration does not authorize granting the "%s" ability to this subject.',
            $ability,
        ));
    }

    public static function lifetimeWidening(): self
    {
        return new self(
            'The requested lifetime widens past what the declaration authorizes for this subject. '
            .'Choose an expiry within the declared maximum; the package never substitutes one.',
        );
    }

    public static function unsupportedField(string $field): self
    {
        return new self(sprintf(
            'The declaration marks "%s" unsupported for this app; a mint cannot set it.',
            $field,
        ));
    }

    /**
     * D6 point 6's third row, refused EXPLICITLY rather than falling
     * through to bearer semantics: hmac rotation is the pending→active
     * cutover (rotate creates the new key pending while the old keeps
     * signing; delivery installs it receiver-side; activation cuts over)
     * and ships with the hmac kind itself (D9).
     */
    public static function kindNotRotatable(string $kind): self
    {
        return new self(sprintf(
            'The "%s" credential kind does not rotate in this release: its rotation is the pending-then-activate '
            .'cutover (rotate mints the new key pending, delivery installs it receiver-side, activation cuts signing '
            .'over), which ships with the kind itself. Nothing fell through to bearer semantics.',
            $kind,
        ));
    }

    /**
     * The fail-closed override answer (PRD 1.7, D6 point 4): overrides are
     * opt-in via AuthorizesRotationOverrides, so "not opted in" and
     * "opted in and denied" refuse identically — a caller learns only
     * that THIS override is not authorized, never which gate said no.
     */
    public static function overrideNotAuthorized(): self
    {
        return new self(
            'The declaration does not authorize this rotation override for this subject. '
            .'Overrides are opt-in: a declaration that has not opted in denies every one.',
        );
    }
}
