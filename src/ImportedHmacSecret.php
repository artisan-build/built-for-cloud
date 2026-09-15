<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use JsonSerializable;
use LogicException;
use SensitiveParameter;
use WeakMap;

/** @internal Plaintext received from the authenticated issuer client. */
final class ImportedHmacSecret implements JsonSerializable
{
    /** @var WeakMap<self, string>|null */
    private static ?WeakMap $plaintexts = null;

    private bool $revealed = false;

    private function __construct(#[SensitiveParameter] string $plaintext)
    {
        self::$plaintexts ??= new WeakMap;
        self::$plaintexts[$this] = $plaintext;
    }

    /** @internal Constructs a sealed secret parsed from an issuer response. */
    public static function fromIssuerResponse(#[SensitiveParameter] string $plaintext): self
    {
        return new self($plaintext);
    }

    public function reveal(): string
    {
        if ($this->revealed || self::$plaintexts === null || ! self::$plaintexts->offsetExists($this)) {
            throw new LogicException('This imported HMAC secret has already been revealed.');
        }

        $plaintext = self::$plaintexts[$this];
        unset(self::$plaintexts[$this]);
        $this->revealed = true;

        return $plaintext;
    }

    /** @return array<string, mixed> */
    public function __serialize(): array
    {
        throw new LogicException('An imported HMAC secret never serializes.');
    }

    /** @return list<string> */
    public function __sleep(): array
    {
        throw new LogicException('An imported HMAC secret never serializes.');
    }

    public function jsonSerialize(): never
    {
        throw new LogicException('An imported HMAC secret never JSON-encodes.');
    }

    public function __clone()
    {
        throw new LogicException('An imported HMAC secret never clones.');
    }
}
