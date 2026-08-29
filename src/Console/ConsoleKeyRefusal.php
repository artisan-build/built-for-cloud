<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

use ArtisanBuild\BuiltForCloud\Exceptions\ConsoleKeyRefused;

/**
 * Why a countersigning-key delivery was refused (Console PRD D12).
 *
 * The property every one of these defends is the same: **whoever
 * controls a filed key controls who may enter this deployment as an
 * admin.** Every path that writes a keyring row is a takeover path, so
 * each reason below is a gate on that, not a validation nicety.
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
     * This exact key material is already on the ring under some key id
     * (rework B4). Refused in EVERY lifecycle state of the existing row
     * — pending, active, and above all RETIRED.
     *
     * Retirement is the only revocation this design has: a console key
     * has no expiry, there is no revocation list, and nothing can reach
     * back into assertions already minted. Without this rule a retired
     * key's material could simply be re-filed under a fresh key id and
     * would verify again, which would make retirement a suggestion.
     */
    case MaterialAlreadyFiled = 'console_key_material_already_filed';

    /**
     * The claim code presented carries no key-custody authority — it was
     * never issued with it, or it has already spent it (rework B1).
     *
     * One reason covers both on purpose. A code that has spent its
     * authority no longer has any, so there is nothing to distinguish,
     * and answering differently would tell a code's holder whether some
     * OTHER party had already used it.
     */
    case NotAuthorized = 'console_key_delivery_not_authorized';

    /**
     * Another delivery filed a conflicting key id, or conflicting key
     * material, in the instant between this delivery's checks and its
     * insert (rework Advisory 1).
     *
     * ONE reason for both constraints, deliberately. Working out WHICH
     * unique index lost would mean either re-reading the table — which
     * PostgreSQL forbids inside the transaction the violation just
     * aborted — or matching driver-specific error text. Neither is
     * worth it for an outcome the caller handles identically: nothing
     * was written, re-read the ring and deliver again. The named
     * {@see self::KeyIdInUse} and {@see self::MaterialAlreadyFiled}
     * refusals still answer every non-racing delivery, which is every
     * delivery a real operator makes.
     */
    case ConcurrentDelivery = 'console_key_delivery_raced';

    /**
     * Nobody owns this deployment yet (rework A6). A countersigning key
     * names the vendor who may enter as admin, and a deployment with no
     * owner has not yet decided who that is; filing one first would let
     * whoever reached the box first install the trust root.
     *
     * The ownership claim is the one path exempt from this by
     * construction: it establishes the owner and files the key in the
     * same transaction, in that order.
     */
    case Unclaimed = 'deployment_not_claimed';

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
            self::KeyIdInUse, self::MaterialAlreadyFiled, self::Unclaimed, self::ConcurrentDelivery => 409,
            // Not 401: the caller authenticated fine. What it presented
            // simply does not carry this authority.
            self::NotAuthorized => 403,
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
            self::MaterialAlreadyFiled => 'That console key is already on file under an existing key id. Key material is filed once per deployment, retired keys included — deliver a freshly generated key instead.',
            self::NotAuthorized => 'This claim code does not carry console key-custody authority. Ask the operator to issue a code with console_key_authority, which files exactly one key.',
            self::Unclaimed => 'This deployment has not been claimed, so there is no owner to countersign for. Claim ownership first; the ownership claim can deliver a console key in the same request.',
            self::ConcurrentDelivery => 'Another console key delivery landed at the same moment and claimed this key id or this key material. Nothing was written by this request; re-read the keyring and deliver again under a fresh key id.',
        };
    }
}
