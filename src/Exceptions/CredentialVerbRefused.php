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

    public static function kindNotMintable(string $kind): self
    {
        return new self(sprintf('The "%s" credential kind is not mintable in this release.', $kind));
    }
}
