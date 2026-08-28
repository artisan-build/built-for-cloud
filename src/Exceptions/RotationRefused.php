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
     * and A→C), and supersession that forks answers nothing. Thrown only
     * when no LIVE successor stands (re-invoking the verb on a stamped
     * row with a live successor performs cutover completion instead):
     * with the whole chain dead there is nothing to complete and nothing
     * to rotate — mint a fresh credential.
     */
    public static function alreadyRotated(string $id, ?string $successorId): self
    {
        return new self(sprintf(
            'Credential %s was already superseded by rotation%s, and its successor is no longer live: '
            .'there is no cutover to complete, and rotating the stamped row again would fork the lineage. '
            .'Mint a fresh credential instead.',
            $id,
            $successorId !== null ? sprintf(' (by credential %s)', $successorId) : '',
        ));
    }

    /**
     * The hmac dance mid-flight: the stamped source's replacement is
     * still PENDING activation, so there is no cutover to complete (the
     * old key still owns signing) and nothing to re-rotate.
     */
    public static function successorAwaitingActivation(string $id, string $successorId): self
    {
        return new self(sprintf(
            'Credential %s was already rotated; its replacement %s is still PENDING activation, and the old key '
            .'keeps signing until the cutover. Activate the replacement (bfc:credential:activate %s) — or revoke '
            .'it by id to abandon the rotation, or revoke %s by id if the old key is compromised and must die now.',
            $id,
            $successorId,
            $successorId,
            $id,
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
