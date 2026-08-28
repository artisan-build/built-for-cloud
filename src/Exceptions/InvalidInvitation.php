<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Exceptions;

use ArtisanBuild\BuiltForCloud\ClaimError;
use RuntimeException;

/**
 * The invitation accept path speaks the claim contract's error enum (PRD
 * 1.13, D1e): callers branch on {@see $error}, never on message prose. The
 * message is human text that may be printed verbatim, so it never carries
 * the presented code or any other secret.
 */
final class InvalidInvitation extends RuntimeException
{
    private function __construct(
        string $message,
        public readonly ClaimError $error,
    ) {
        parent::__construct($message);
    }

    public static function notFound(): self
    {
        return new self(
            'No invitation matches the code presented. Ask the issuer for a new one.',
            ClaimError::CodeNotFound,
        );
    }

    public static function alreadyAccepted(): self
    {
        return new self(
            'This invitation was already accepted. Ask the issuer for a new one.',
            ClaimError::CodeAlreadyClaimed,
        );
    }

    public static function expired(): self
    {
        return new self(
            'This invitation has expired. Ask the issuer for a new one.',
            ClaimError::CodeExpired,
        );
    }

    /**
     * @deprecated Use the enum-specific factories. Kept so pre-1.13 catch
     * sites constructing this shape keep compiling; the token is accepted
     * and deliberately IGNORED — the old message embedded it, which leaked
     * the plaintext code into the exception channel.
     */
    public static function forToken(string $token): self
    {
        return new self(
            'The invitation code presented is invalid, expired, or already accepted.',
            ClaimError::CodeNotFound,
        );
    }
}
