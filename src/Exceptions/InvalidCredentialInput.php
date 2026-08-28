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
}
