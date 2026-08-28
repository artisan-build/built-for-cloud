<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Exceptions;

use RuntimeException;

/**
 * Activation refused because of the TARGET's state (the same taxonomy as
 * {@see RotationRefused}): the request was well-formed and authorized, but
 * the row it names cannot be activated as asked. Both transports refuse
 * identically — the CLI as a failure exit, HTTP as a 409. Never carries a
 * secret.
 *
 * Activation is the hmac kind's pending→active signing cutover
 * (SEC-V3-01): a SEPARATE operator-authorized transition, taken after the
 * receiver confirms installation out-of-band. Nothing else — not the mint,
 * not the exchange — may flip live signing state.
 */
final class ActivationRefused extends RuntimeException
{
    public static function wrongKind(string $kind): self
    {
        return new self(sprintf(
            'Activation is the hmac kind\'s signing cutover; a "%s" credential has no pending→active transition to take.',
            $kind,
        ));
    }

    /**
     * Premature activation (locked AC 3): the key was never delivered —
     * neither revealed at mint nor exchanged through its claim link — so
     * the receiver cannot have installed it, and cutting signing over to
     * it would break every message.
     */
    public static function notDelivered(string $id): self
    {
        return new self(sprintf(
            'Credential %s has not been delivered: its signing key was neither revealed at mint nor exchanged '
            .'through its claim link, so the receiver cannot have installed it. Deliver the key (the receiver '
            .'exchanges the claim code), confirm installation out-of-band, then activate.',
            $id,
        ));
    }

    /**
     * Duplicate activation — REFUSED, not idempotent (the stated
     * semantics): a second activation of a live key is a real signal that
     * two operators disagree about cutover state, and a loud refusal makes
     * the second one look before assuming.
     */
    public static function alreadyActive(string $id): self
    {
        return new self(sprintf(
            'Credential %s is already active: its cutover already happened. Activation is deliberately not '
            .'idempotent — if you expected this key to be pending, check the audit stream before assuming.',
            $id,
        ));
    }

    /**
     * The stale-confirmation refusal (SEC-V3-01 rework, finding 1): the
     * fingerprint the operator confirmed is not the row's CURRENT
     * delivery — a redelivery re-keyed the row after that confirmation
     * was made, so activating on its strength would cut signing over to
     * key material the confirmer never saw.
     */
    public static function staleDeliveryConfirmation(string $id): self
    {
        return new self(sprintf(
            'The confirmed delivery is not credential %s\'s current delivery: the key was re-delivered (and '
            .'re-keyed) after that confirmation was made. Ask the receiver which delivery fingerprint they '
            .'actually hold installed, and activate with THAT — a confirmation always names one exact delivery.',
            $id,
        ));
    }

    public static function dead(string $id, string $status): self
    {
        return new self(sprintf(
            'Credential %s is %s; only a live pending signing key can be activated. Mint or rotate a fresh one.',
            $id,
            $status,
        ));
    }
}
