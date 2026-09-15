<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use JsonSerializable;
use LogicException;
use SensitiveParameter;
use WeakMap;

/** A one-use, non-serializable carrier for caller-supplied sensitive text. */
final class SensitiveString implements JsonSerializable
{
    /** @var WeakMap<self, string>|null */
    private static ?WeakMap $values = null;

    private bool $revealed = false;

    public function __construct(#[SensitiveParameter] string $value)
    {
        self::$values ??= new WeakMap;
        self::$values[$this] = $value;
    }

    public function reveal(): string
    {
        if ($this->revealed || self::$values === null || ! self::$values->offsetExists($this)) {
            throw new LogicException('This sensitive string has already been revealed.');
        }

        $value = self::$values[$this];
        unset(self::$values[$this]);
        $this->revealed = true;

        return $value;
    }

    /** @return array<string, mixed> */
    public function __serialize(): array
    {
        throw new LogicException('A sensitive string never serializes.');
    }

    /** @return list<string> */
    public function __sleep(): array
    {
        throw new LogicException('A sensitive string never serializes.');
    }

    public function jsonSerialize(): never
    {
        throw new LogicException('A sensitive string never JSON-encodes.');
    }

    public function __clone()
    {
        throw new LogicException('A sensitive string never clones.');
    }
}
