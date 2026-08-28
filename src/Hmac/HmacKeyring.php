<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Hmac;

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\Exceptions\HmacKeyUnreadable;
use Illuminate\Encryption\Encrypter;
use RuntimeException;
use SensitiveParameter;

/**
 * The hmac kind's encryption keyring (SEC-V3-08): every hmac signing key
 * is stored ENCRYPTED (D9.1 — a hash cannot sign), every ciphertext
 * carries the VERSION of the key that encrypted it, and APP_KEY rotation
 * is a staged cutover instead of a brick.
 *
 * The ring rides Laravel's own staged APP_KEY rotation, deliberately: the
 * WRITE-PRIMARY is `app.key`, and the READ-KEYRING is `app.key` plus every
 * entry of `app.previous_keys` (APP_PREVIOUS_KEYS) — the exact mechanism
 * Laravel already uses to keep old cookies/values decryptable across a key
 * rotation. No new env var, no second key inventory to drift.
 *
 * A key-version is a CONTENT-ADDRESSED fingerprint — the first
 * {@see KEY_VERSION_LENGTH} hex chars of sha256(raw key bytes) — never a
 * position: `previous_keys` is an ordered list humans edit, and "key #2"
 * would silently re-address every ciphertext when someone reorders it.
 * The fingerprint of a secret 32-byte key reveals nothing useful about it.
 *
 * The staged rewrap procedure (the release-note runbook):
 * 1. deploy `APP_PREVIOUS_KEYS` carrying the old key everywhere — old
 *    ciphertexts stay readable on every app version, mixed deploys
 *    tolerated;
 * 2. switch `APP_KEY` to the new key (the write-primary);
 * 3. run `bfc:hmac:rewrap` — locked, restartable — until it verifies
 *    ZERO old-version rows;
 * 4. drop the old key from `APP_PREVIOUS_KEYS`.
 *
 * While any hmac ciphertext still carries a non-primary version, the
 * cutover is IN PROGRESS ({@see cutoverInProgress()}) and hmac activation
 * and rotation refuse with a retry-later error — mixed versions is the
 * honest definition of "mid-cutover", and it needs no lock-state
 * persistence: a rewrap that died mid-run keeps refusing until a re-run
 * completes.
 */
final class HmacKeyring
{
    /**
     * Hex chars of the sha256 fingerprint used as a key-version. 16 (64
     * bits) is far beyond collision reach for the handful of keys a ring
     * ever holds, and short enough to index and read in a listing.
     */
    private const int KEY_VERSION_LENGTH = 16;

    /**
     * The version every NEW ciphertext is written under: the fingerprint
     * of the current `app.key`.
     */
    public function writeVersion(): string
    {
        return self::fingerprint($this->primaryKey());
    }

    public function encrypt(#[SensitiveParameter] string $plaintext): EncryptedHmacKey
    {
        $key = $this->primaryKey();

        return new EncryptedHmacKey(
            ciphertext: $this->encrypterFor($key)->encryptString($plaintext),
            keyVersion: self::fingerprint($key),
        );
    }

    /**
     * Decrypt a stored signing key by the version its row carries. The
     * version SELECTS the key — decryption never tries the whole ring,
     * so a row whose key left the ring fails loudly and names the
     * version, never "mac invalid" roulette.
     */
    public function decrypt(string $ciphertext, ?string $keyVersion): string
    {
        if ($keyVersion === null || $keyVersion === '') {
            throw HmacKeyUnreadable::missingVersion();
        }

        foreach ($this->readKeys() as $key) {
            if (hash_equals(self::fingerprint($key), $keyVersion)) {
                return $this->encrypterFor($key)->decryptString($ciphertext);
            }
        }

        throw HmacKeyUnreadable::unknownVersion($keyVersion);
    }

    /**
     * Whether an APP_KEY cutover over the hmac store is in progress: any
     * hmac ciphertext row still carrying a non-primary key-version. This
     * is what pauses hmac activation and rotation (SEC-V3-08).
     */
    public function cutoverInProgress(): bool
    {
        return Credential::query()
            ->where('kind', CredentialKind::Hmac->value)
            ->whereNotNull('secret_ciphertext')
            ->where(function ($query): void {
                $query->whereNull('secret_key_version')
                    ->orWhere('secret_key_version', '!=', $this->writeVersion());
            })
            ->exists();
    }

    public static function fingerprint(#[SensitiveParameter] string $rawKeyBytes): string
    {
        return substr(hash('sha256', $rawKeyBytes), 0, self::KEY_VERSION_LENGTH);
    }

    /**
     * The DELIVERY fingerprint (SEC-V3-01 rework): a non-recoverable
     * identifier of one specific delivery of one specific signing key —
     * a domain-separated hash over the key material and the delivery
     * generation, never the key itself. The receiver quotes it back
     * out-of-band, and the activation verb requires it, so a stale
     * confirmation cannot activate key material the confirmer never saw.
     * Deliberately independent of the CIPHERTEXT: an APP_KEY rewrap
     * re-encrypts the same key and must not invalidate a standing
     * confirmation.
     */
    public function deliveryFingerprint(#[SensitiveParameter] string $signingKey, int $generation): string
    {
        return substr(hash('sha256', 'bfc-hmac-delivery|'.$generation.'|'.hash('sha256', $signingKey)), 0, 16);
    }

    private function encrypterFor(#[SensitiveParameter] string $key): Encrypter
    {
        return new Encrypter($key, $this->cipher());
    }

    private function primaryKey(): string
    {
        $key = config('app.key');

        if (! is_string($key) || $key === '') {
            throw new RuntimeException('The hmac keyring requires app.key to be set.');
        }

        return self::parseKey($key);
    }

    /**
     * The read-keyring: the write-primary first, then every previous key,
     * in declared order.
     *
     * @return list<string>
     */
    private function readKeys(): array
    {
        $keys = [$this->primaryKey()];

        $previous = config('app.previous_keys');

        foreach (is_array($previous) ? $previous : [] as $key) {
            if (is_string($key) && $key !== '') {
                $keys[] = self::parseKey($key);
            }
        }

        return $keys;
    }

    private function cipher(): string
    {
        $cipher = config('app.cipher');

        return is_string($cipher) && $cipher !== '' ? $cipher : 'AES-256-CBC';
    }

    /**
     * Laravel's own key notation: a `base64:` prefix carries the raw bytes
     * base64-encoded; anything else is the raw key.
     */
    private static function parseKey(#[SensitiveParameter] string $key): string
    {
        if (str_starts_with($key, 'base64:')) {
            $decoded = base64_decode(substr($key, 7), true);

            if ($decoded === false) {
                throw new RuntimeException('An app key declared as base64 does not decode.');
            }

            return $decoded;
        }

        return $key;
    }
}
