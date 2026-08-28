<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Hmac;

/**
 * What {@see HmacKeyring::encrypt()} returns: the ciphertext AND the
 * version of the encryption key that produced it, together — a ciphertext
 * without its key-version is unreadable the moment the APP_KEY rotates
 * (SEC-V3-08), so the two are one value and land in the store as one
 * write.
 */
final readonly class EncryptedHmacKey
{
    public function __construct(
        public string $ciphertext,
        public string $keyVersion,
    ) {}
}
