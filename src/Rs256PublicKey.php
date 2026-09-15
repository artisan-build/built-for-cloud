<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use OpenSSLAsymmetricKey;

/** One canonical RSA SubjectPublicKeyInfo key suitable for RS256. */
final readonly class Rs256PublicKey
{
    public const int MAX_BYTES = 16384;

    public string $pem;

    public function __construct(string $publicKey)
    {
        if (strlen($publicKey) > self::MAX_BYTES
            || preg_match('/-----BEGIN[A-Z0-9 ]*PRIVATE KEY-----/i', $publicKey) === 1
            || substr_count($publicKey, '-----BEGIN PUBLIC KEY-----') !== 1
            || substr_count($publicKey, '-----END PUBLIC KEY-----') !== 1) {
            throw InvalidCredentialInput::invalidRs256PublicKey();
        }

        $normalized = str_replace("\r\n", "\n", trim($publicKey, " \t\n\r\0\x0B\f"));

        if (str_contains($normalized, "\r")
            || preg_match('/\A-----BEGIN PUBLIC KEY-----\n([A-Za-z0-9+\/=\n]+)\n-----END PUBLIC KEY-----\z/D', $normalized, $matches) !== 1) {
            throw InvalidCredentialInput::invalidRs256PublicKey();
        }

        $encoded = str_replace("\n", '', $matches[1]);
        $decoded = base64_decode($encoded, true);

        if ($decoded === false || base64_encode($decoded) !== $encoded) {
            throw InvalidCredentialInput::invalidRs256PublicKey();
        }

        $key = openssl_pkey_get_public($normalized."\n");

        if (! $key instanceof OpenSSLAsymmetricKey) {
            throw InvalidCredentialInput::invalidRs256PublicKey();
        }

        $details = openssl_pkey_get_details($key);

        if (! is_array($details)
            || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_RSA
            || ! is_int($details['bits'] ?? null)
            || $details['bits'] < 2048
            || $details['bits'] > 8192
            || ! is_string($details['key'] ?? null)) {
            throw InvalidCredentialInput::invalidRs256PublicKey();
        }

        $canonical = str_replace("\r\n", "\n", $details['key']);
        $this->pem = rtrim($canonical, "\n")."\n";
    }

    public function algorithm(): CredentialAlgorithm
    {
        return CredentialAlgorithm::Rs256;
    }
}
