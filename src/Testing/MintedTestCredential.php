<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use ArtisanBuild\BuiltForCloud\Credential;
use JsonSerializable;
use LogicException;
use SensitiveParameter;
use WeakMap;

/**
 * A credential row plus the in-memory plaintext a test presents. The
 * plaintext exists ONLY here, in test memory — the store persists the hash.
 *
 * The carrier is sealed: it refuses PHP serialization and JSON encoding
 * (both throw), has no string conversion, and the plaintext is held OUTSIDE
 * the object (a class-level WeakMap keyed by instance), so native export and
 * debug paths — var_export, print_r, var_dump, get_object_vars, a reflection
 * property walk — see no secret either. A queued payload, cache write,
 * object logger or component snapshot cannot carry the secret out of the
 * test. This is the test-only carrier; the production sealed carrier ships
 * with the mint verb in a later release.
 */
final class MintedTestCredential implements JsonSerializable
{
    /**
     * @var WeakMap<self, string>|null
     */
    private static ?WeakMap $plaintexts = null;

    public function __construct(
        public readonly Credential $credential,
        #[SensitiveParameter] string $plaintext,
    ) {
        self::$plaintexts ??= new WeakMap;
        self::$plaintexts[$this] = $plaintext;
    }

    public function plaintext(): string
    {
        if (self::$plaintexts === null || ! self::$plaintexts->offsetExists($this)) {
            throw new LogicException('This carrier no longer holds a plaintext.');
        }

        return self::$plaintexts[$this];
    }

    public function bearerHeader(): string
    {
        return 'Bearer '.$this->plaintext();
    }

    /**
     * The Composer `auth.json` shape: the username is decorative, the
     * password is the secret.
     */
    public function basicHeader(string $username = 'token'): string
    {
        return 'Basic '.base64_encode($username.':'.$this->plaintext());
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
