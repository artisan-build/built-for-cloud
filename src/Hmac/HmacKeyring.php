<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Hmac;

use ArtisanBuild\BfcClient\Hmac\EncryptedHmacKey;
use ArtisanBuild\BfcClient\Hmac\HmacKeyring as SharedHmacKeyring;
use SensitiveParameter;

/** @deprecated Use ArtisanBuild\BfcClient\Hmac\HmacKeyring. */
final class HmacKeyring
{
    public function __construct(private ?SharedHmacKeyring $shared = null) {}

    public function writeVersion(): string
    {
        return $this->implementation()->writeVersion();
    }

    public function encrypt(#[SensitiveParameter] string $plaintext): EncryptedHmacKey
    {
        return $this->implementation()->encrypt($plaintext);
    }

    public function decrypt(string $ciphertext, ?string $keyVersion): string
    {
        return $this->implementation()->decrypt($ciphertext, $keyVersion);
    }

    public function cutoverInProgress(): bool
    {
        return $this->implementation()->cutoverInProgress();
    }

    public static function fingerprint(#[SensitiveParameter] string $rawKeyBytes): string
    {
        return SharedHmacKeyring::fingerprint($rawKeyBytes);
    }

    public function deliveryFingerprint(#[SensitiveParameter] string $signingKey, int $generation): string
    {
        return $this->implementation()->deliveryFingerprint($signingKey, $generation);
    }

    /** @internal */
    public function implementation(): SharedHmacKeyring
    {
        return $this->shared ??= app(SharedHmacKeyring::class);
    }
}
