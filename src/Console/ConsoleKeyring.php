<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

use ArtisanBuild\BuiltForCloud\Exceptions\AssertionRefused;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use Carbon\CarbonImmutable;
use InvalidArgumentException;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Keys\Version4\AsymmetricPublicKey;
use Throwable;

/**
 * The app's copy of the vendor's per-deployment PUBLIC keys (Console PRD
 * D12). It is the console half of what {@see HmacKeyring} is to the hmac
 * kind — a key id selects exactly one key, never a "try them all" loop —
 * with one decisive difference: **this ring is not built to hold secret
 * material.** There is no store method for a private key, no column
 * named for one, and — decisively — NO CODE PATH ANYWHERE IN THIS
 * PACKAGE THAT SIGNS. The vendor signs; this app only verifies; a full
 * dump of this table hands an attacker nothing but the ability to check
 * signatures they still cannot produce.
 *
 * Be precise about where that guarantee comes from, because
 * {@see normalizePublicKey()} cannot supply it. An Ed25519 SEED — the
 * private half in its compact 32-byte form — is 32 bytes like a public
 * key, and roughly one seed in twenty happens to encode a valid curve
 * point, at which point nothing distinguishes it from a public key by
 * inspection. The custody property is therefore held by the PROVISIONING
 * PROTOCOL (the vendor hands over the public half; nothing here ever
 * asks for, transports, or accepts a private one) and by this package
 * having nothing to sign with, NOT by the validation below. What the
 * validation does buy is that mis-delivered, truncated or corrupt
 * material fails loudly at delivery instead of silently refusing every
 * assertion at 3am.
 *
 * Rotation is make-before-break and its two halves are two operations:
 *
 * 1. {@see add()} files a NEW key as pending — receiving key material is
 *    not trusting it;
 * 2. {@see activate()} starts trusting it and touches NO OTHER ROW, so
 *    the outgoing key keeps verifying — both are active at once;
 * 3. {@see retire()} stops trusting the outgoing key, LATER, once every
 *    assertion minted under it has expired (D12 caps that at
 *    `assertion_max_ttl_seconds`, so the safe wait is short and known).
 *
 * Fusing 2 and 3 into one "rotate" call is the classic way to make a
 * rotation an outage: every assertion minted in the seconds before the
 * switch would land against a key that had just stopped existing.
 *
 * Stored form is lower-case hex of the 32 raw bytes. Callers may hand in
 * hex or unpadded base64url (what PASETO's own `encode()` emits) — both
 * normalize to the same row, so the same key delivered through two
 * transports can never file as two different keys.
 */
final class ConsoleKeyring
{
    /**
     * Ed25519 public keys are 32 bytes — 64 hex characters. Nothing of
     * another length stores, which does rule out the 64-BYTE expanded
     * Ed25519 secret key (128 hex characters); it does NOT rule out a
     * 32-byte seed, which is the same size as a public key. See the
     * custody paragraph in the class docblock.
     */
    public const int PUBLIC_KEY_BYTES = 32;

    /**
     * The `kid` charset: bounded, and free of anything that could ride
     * into a log line, a URL, or the token footer's JSON as structure.
     * Anchored with `\z` rather than `$` because PHP's `$` also matches
     * before a trailing newline — "k1\n" would otherwise pass as "k1".
     */
    private const string KEY_ID_PATTERN = '/^[A-Za-z0-9._-]{1,64}\z/';

    /**
     * File a key as PENDING. Deliberately refuses to overwrite an
     * existing key id: silently replacing the material behind a live
     * `kid` is key substitution — the one write that would let a
     * mis-delivered key inherit an already-trusted name.
     *
     * Refusals here are {@see InvalidArgumentException}, not
     * {@see AssertionRefused}: this is an operator/exchange path, and a
     * malformed key delivery must fail LOUDLY at the caller rather than
     * quietly become a verification that refuses everything later.
     */
    public function add(string $keyId, string $publicKey): ConsoleKey
    {
        $this->assertValidKeyId($keyId);

        if ($this->find($keyId) instanceof ConsoleKey) {
            throw new InvalidArgumentException('A console key with that key id is already on file.');
        }

        return ConsoleKey::query()->create([
            'key_id' => $keyId,
            'public_key' => self::normalizePublicKey($publicKey),
        ]);
    }

    /**
     * Start trusting a filed key. Touches no other row — the overlap
     * with the outgoing key is the whole point of make-before-break.
     * Re-activating an already-active key is a no-op rather than a
     * lifetime reset.
     */
    public function activate(string $keyId): ConsoleKey
    {
        $key = $this->requireKey($keyId);

        if ($key->activated_at === null) {
            $key->forceFill(['activated_at' => CarbonImmutable::now()])->save();
        }

        return $key;
    }

    /**
     * Stop trusting a key, permanently. Separate from activation on
     * purpose, and separately audited by whoever calls it.
     */
    public function retire(string $keyId): ConsoleKey
    {
        $key = $this->requireKey($keyId);

        if ($key->retired_at === null) {
            $key->forceFill(['retired_at' => CarbonImmutable::now()])->save();
        }

        return $key;
    }

    public function find(string $keyId): ?ConsoleKey
    {
        if (! self::isValidKeyId($keyId)) {
            return null;
        }

        return ConsoleKey::query()->where('key_id', $keyId)->first();
    }

    /**
     * Whether a string is a well-formed `kid`. Exposed so the delivery
     * surfaces can refuse a malformed id BEFORE opening a transaction
     * (and before echoing it into an audit note) against the same
     * pattern this ring enforces — one regex, never a second copy that
     * could drift from it.
     */
    public static function isValidKeyId(string $keyId): bool
    {
        return preg_match(self::KEY_ID_PATTERN, $keyId) === 1;
    }

    /**
     * Every key that verifies right now — normally one, and exactly two
     * for the duration of a rotation.
     *
     * @return list<ConsoleKey>
     */
    public function active(?CarbonImmutable $at = null): array
    {
        $at ??= CarbonImmutable::now();

        return ConsoleKey::query()
            ->whereNotNull('activated_at')
            ->where('activated_at', '<=', $at)
            ->where(function ($query) use ($at): void {
                $query->whereNull('retired_at')->orWhere('retired_at', '>', $at);
            })
            ->orderBy('key_id')
            ->get()
            ->all();
    }

    /**
     * Resolve the verification key a token's `kid` names, at one instant.
     *
     * The three misses answer with three DIFFERENT reasons — unknown,
     * pending, retired — which departs from the hmac verifier's single
     * indistinct "unusable key". That is safe here and wanted: the
     * reason never reaches the caller ({@see AssertionRefused} carries
     * one uniform message for all thirteen), and rotation is exactly the
     * operation where an operator staring at an audit record needs to
     * know whether the deployment is presenting a key nobody filed or a
     * key retired an hour too early.
     *
     * @throws AssertionRefused
     */
    public function verificationKey(string $keyId, CarbonImmutable $at): AsymmetricPublicKey
    {
        $key = $this->find($keyId);

        if (! $key instanceof ConsoleKey) {
            throw AssertionRefused::because(AssertionRefusalReason::UnknownKey);
        }

        if ($key->isRetiredAt($at)) {
            throw AssertionRefused::because(AssertionRefusalReason::RetiredKey);
        }

        if ($key->isPendingAt($at)) {
            throw AssertionRefused::because(AssertionRefusalReason::KeyNotActive);
        }

        try {
            return new AsymmetricPublicKey($key->public_key);
        } catch (PasetoException $failure) {
            // A row that cannot become a key is a storage fault, not a
            // property of the presented token: refuse the token (never
            // 500 the endpoint) and keep the cause for the operator log.
            throw AssertionRefused::because(AssertionRefusalReason::UnknownKey, $failure);
        }
    }

    /**
     * Normalize a delivered public key to storage form, refusing an
     * unparseable encoding, anything that is not exactly 32 bytes (a
     * truncated key, a PEM blob, the 64-byte expanded secret key), and
     * any 32 bytes that are not a usable Ed25519 point.
     *
     * The point check is what makes a delivery fail at delivery: a
     * mistyped or corrupted key that merely LOOKS like 32 bytes would
     * otherwise file happily and then refuse every assertion minted
     * against it. It is not a custody control — see the class docblock
     * for where custody actually comes from.
     */
    public static function normalizePublicKey(string $publicKey): string
    {
        $raw = self::decode($publicKey);

        if ($raw === null || strlen($raw) !== self::PUBLIC_KEY_BYTES) {
            throw new InvalidArgumentException('A console key must be a 32-byte Ed25519 public key.');
        }

        if (! self::isUsableEd25519Point($raw)) {
            throw new InvalidArgumentException('A console key must be 32 bytes encoding a usable Ed25519 point.');
        }

        return bin2hex($raw);
    }

    /**
     * Whether 32 bytes are a canonical, non-small-order Ed25519 point on
     * the main subgroup — libsodium's own `crypto_core_ed25519_is_valid_point`
     * test, reached the only way PHP exposes it.
     *
     * PHP's ext-sodium ships the `crypto_core_*` family for ristretto255
     * ONLY; there is no `sodium_crypto_core_ed25519_is_valid_point()` to
     * call. `crypto_sign_ed25519_pk_to_curve25519()` runs the identical
     * three checks internally — small order, decodable, on the main
     * subgroup — and fails if any of them does, so converting the key
     * and discarding the result is the available spelling of the same
     * question. It is present with or without ext-sodium: paseto's own
     * dependency sodium_compat polyfills the function, and its pure-PHP
     * path refuses the same values — throwing RangeException rather than
     * SodiumException for some of them, which is why the catch below is
     * on Throwable and not on one exception class.
     */
    private static function isUsableEd25519Point(string $rawKeyBytes): bool
    {
        try {
            sodium_crypto_sign_ed25519_pk_to_curve25519($rawKeyBytes);
        } catch (Throwable) {
            return false;
        }

        return true;
    }

    /**
     * Accept the two encodings a delivered key realistically arrives in
     * — hex, and the unpadded base64url PASETO's own `encode()` emits —
     * and nothing else. Both are strict: a string that is not entirely
     * one of them decodes to null rather than to a truncated key.
     */
    private static function decode(string $publicKey): ?string
    {
        if (preg_match('/^[0-9a-fA-F]+\z/', $publicKey) === 1 && strlen($publicKey) % 2 === 0) {
            $hex = hex2bin(strtolower($publicKey));

            return $hex === false ? null : $hex;
        }

        if (preg_match('/^[A-Za-z0-9_-]+\z/', $publicKey) !== 1) {
            return null;
        }

        $decoded = base64_decode(strtr($publicKey, '-_', '+/'), true);

        return $decoded === false ? null : $decoded;
    }

    private function requireKey(string $keyId): ConsoleKey
    {
        $key = $this->find($keyId);

        if (! $key instanceof ConsoleKey) {
            throw new InvalidArgumentException('No console key with that key id is on file.');
        }

        return $key;
    }

    private function assertValidKeyId(string $keyId): void
    {
        if (! self::isValidKeyId($keyId)) {
            throw new InvalidArgumentException('A console key id must be 1-64 characters of [A-Za-z0-9._-].');
        }
    }
}
