<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

use ArtisanBuild\BuiltForCloud\Exceptions\ConsoleKeyRefused;

/**
 * Why a countersigning-key delivery was refused (Console PRD D12). Two
 * reasons, because {@see ConsoleKeyring} enforces exactly two rules on a
 * delivery: the material must be a canonical 32-byte Ed25519 public key
 * under a well-formed `kid`, and a `kid` already on file is never
 * overwritten.
 *
 * Unlike {@see AssertionRefusalReason} — whose reasons are deliberately
 * invisible to the presenter, because there the presenter may be an
 * attacker probing a signature — these reasons DO reach the caller, on
 * both transports. The delivery surfaces are operator surfaces or a
 * claim the vendor is performing against its own deployment: the caller
 * is the party that has to fix the delivery, and telling them "that key
 * id is taken" rather than "no" is what makes the retrofit path (D12's
 * re-key) operable. Neither message ever echoes delivered key material.
 */
enum ConsoleKeyRefusal: string
{
    /**
     * The `kid` or the key material is not what the ring stores. Note
     * what this reason does NOT mean: it is not a statement that the
     * material is a PUBLIC key. A 32-byte Ed25519 SEED — the private
     * half in compact form — is the same size as a public key and, when
     * it happens to encode a usable curve point, files exactly like one.
     * Custody is held by the provisioning protocol and by this package
     * owning no signing path, never by this check
     * ({@see ConsoleKeyring}'s class docblock states where).
     */
    case InvalidMaterial = 'invalid_key_material';

    /**
     * The `kid` already names a key on this ring. The ring refuses to
     * rebind a live `kid` to different bytes (that is key substitution),
     * and it does not special-case a redelivery of the same bytes: one
     * `kid`, one key, for the life of the row. A retrofit or rotation
     * delivers a NEW `kid`.
     */
    case KeyIdInUse = 'console_key_id_in_use';

    /**
     * The status the HTTP transports answer with. `409` for the taken
     * `kid` — a conflict with existing state, exactly as the ownership
     * claim answers a second claimant — and `422` for material this
     * server will never accept however often it is re-sent.
     */
    public function status(): int
    {
        return match ($this) {
            self::InvalidMaterial => 422,
            self::KeyIdInUse => 409,
        };
    }

    /**
     * The operator-facing prose, printed verbatim by clients
     * ({@see ConsoleKeyRefused} carries it). Server-authored and
     * constant: it never interpolates anything the caller delivered.
     */
    public function message(): string
    {
        return match ($this) {
            self::InvalidMaterial => 'A console countersigning key must be a canonical 32-byte Ed25519 public key (hex or unpadded base64url) under a key id of 1-64 characters of [A-Za-z0-9._-].',
            self::KeyIdInUse => 'That console key id is already on file. A key id names exactly one key for the life of this deployment; deliver the replacement under a new key id.',
        };
    }
}
