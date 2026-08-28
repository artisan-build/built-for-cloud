<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use ArtisanBuild\BuiltForCloud\Credential;
use JsonSerializable;
use LogicException;

/**
 * A credential row plus the in-memory plaintext a test presents. The
 * plaintext exists ONLY here, in test memory — the store persists the hash.
 *
 * The carrier is sealed: it refuses PHP serialization and JSON encoding
 * (both throw) and has no string conversion, so a queued payload, cache
 * write, object logger or component snapshot cannot carry the secret out of
 * the test.
 */
final readonly class MintedTestCredential implements JsonSerializable
{
    public function __construct(
        public Credential $credential,
        public string $plaintext,
    ) {}

    public function bearerHeader(): string
    {
        return 'Bearer '.$this->plaintext;
    }

    /**
     * The Composer `auth.json` shape: the username is decorative, the
     * password is the secret.
     */
    public function basicHeader(string $username = 'token'): string
    {
        return 'Basic '.base64_encode($username.':'.$this->plaintext);
    }

    /**
     * @return array<string, mixed>
     */
    public function __serialize(): array
    {
        throw new LogicException('A minted test credential never serializes: the plaintext lives only in test memory.');
    }

    /**
     * @return list<string>
     */
    public function __sleep(): array
    {
        throw new LogicException('A minted test credential never serializes: the plaintext lives only in test memory.');
    }

    public function jsonSerialize(): never
    {
        throw new LogicException('A minted test credential never JSON-encodes: the plaintext lives only in test memory.');
    }
}
