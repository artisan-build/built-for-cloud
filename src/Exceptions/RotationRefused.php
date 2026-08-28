<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Exceptions;

use RuntimeException;

/**
 * Rotation refused because of the TARGET's state — distinct from
 * {@see CredentialVerbRefused} (an authority answer) and from
 * {@see InvalidCredentialInput} (malformed input): the request was
 * well-formed and authorized, but the row it names cannot be rotated as
 * asked. Thrown by the shared rotation implementations so both transports
 * refuse identically: the CLI maps it to a failure exit, the HTTP surfaces
 * to a 409. Never carries a secret.
 *
 * The name-path refusals are D6 point 2 / SEC-5: name-based rotation
 * refuses whenever more than one resolvable source row exists — never
 * "which lifetime wins" guessing, never picking one — and rotation never
 * mints on a name with nothing behind it (a rotate is a REPLACEMENT; the
 * mint verbs create).
 */
final class RotationRefused extends RuntimeException
{
    public static function ambiguousName(string $name, int $count): self
    {
        return new self(sprintf(
            '%d resolvable credentials share the name "%s"; a name-based rotation never picks one. Rotate by id.',
            $count,
            $name,
        ));
    }

    public static function unknownName(string $name): self
    {
        return new self(sprintf(
            'No resolvable credential is named "%s"; rotation replaces an existing credential and never mints a first one.',
            $name,
        ));
    }

    public static function sourceNotResolvable(string $id): self
    {
        return new self(sprintf(
            'Credential %s no longer resolves (revoked or expired); there is nothing to rotate. Mint a replacement instead.',
            $id,
        ));
    }

    public static function sourceDead(string $id, string $status): self
    {
        return new self(sprintf(
            'Credential %s is %s; rotation replaces a LIVE credential. Mint a new one instead.',
            $id,
            $status,
        ));
    }

    /**
     * Fold A: a row already superseded by rotation never rotates again —
     * a second rotation of the same source would fork the lineage (A→B
     * and A→C), and supersession that forks answers nothing. The
     * successor is the row to rotate.
     */
    public static function alreadyRotated(string $id, ?string $successorId): self
    {
        return new self(sprintf(
            'Credential %s was already superseded by rotation%s and is living out its grace window; '
            .'rotating it again would fork the lineage. Rotate its replacement instead.',
            $id,
            $successorId !== null ? sprintf(' (by credential %s)', $successorId) : '',
        ));
    }

    public static function sourcePending(string $id): self
    {
        return new self(sprintf(
            'Credential %s is a pending enrollment; it has no secret to rotate. Revoke it and mint a new enrollment instead.',
            $id,
        ));
    }
}
