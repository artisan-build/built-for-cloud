<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

use ArtisanBuild\BuiltForCloud\Exceptions\AssertionRefused;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use Carbon\CarbonImmutable;
use InvalidArgumentException;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Keys\Version4\AsymmetricPublicKey;

/**
 * The app's copy of the vendor's per-deployment PUBLIC keys (Console PRD
 * D12). It is the console half of what {@see HmacKeyring} is to the hmac
 * kind — a key id selects exactly one key, never a "try them all" loop —
 * with one decisive difference: **this ring holds no secret material of
 * any kind.** There is no store method for a private key, no column that
 * can hold one, and no code path that would use one. The vendor signs;
 * this app only verifies; a full dump of this table hands an attacker
 * nothing but the ability to check signatures they still cannot produce.
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
     * Ed25519 public keys are 32 bytes — 64 hex characters. Nothing
     * else is storable, which is also what makes a 64-BYTE Ed25519
     * SECRET key (128 hex characters) unstorable here by construction.
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
        if (preg_match(self::KEY_ID_PATTERN, $keyId) !== 1) {
            return null;
        }

        return ConsoleKey::query()->where('key_id', $keyId)->first();
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
     * Normalize a delivered public key to storage form, refusing
     * anything that is not exactly 32 bytes — a wrong-length string, a
     * PEM blob, an unparseable encoding, or (the one worth naming) a
     * 64-byte Ed25519 SECRET key, which this package must never hold.
     */
    public static function normalizePublicKey(string $publicKey): string
    {
        $raw = self::decode($publicKey);

        if ($raw === null || strlen($raw) !== self::PUBLIC_KEY_BYTES) {
            throw new InvalidArgumentException('A console key must be a 32-byte Ed25519 public key.');
        }

        return bin2hex($raw);
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
        if (preg_match(self::KEY_ID_PATTERN, $keyId) !== 1) {
            throw new InvalidArgumentException('A console key id must be 1-64 characters of [A-Za-z0-9._-].');
        }
    }
}
