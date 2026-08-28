<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use JsonSerializable;
use LogicException;
use SensitiveParameter;
use WeakMap;

/**
 * The sealed carrier every framework-minted plaintext travels in, from mint
 * to its single point of delivery (D7 plaintext containment, PRD 1.8).
 *
 * What it structurally refuses:
 *
 * - The plaintext is held OUTSIDE the object — a class-level WeakMap keyed
 *   by instance — so `var_export`, `print_r`, `var_dump`,
 *   `get_object_vars()`, `json_encode(get_object_vars())` and reflection
 *   walks over the INSTANCE's properties see no secret.
 * - PHP serialization throws (`__serialize` and `__sleep`), so a queued
 *   job payload, cache write, session put or component snapshot cannot
 *   carry it.
 * - `json_encode()` throws (a throwing `jsonSerialize`), so a response
 *   body or log context cannot render it.
 * - There is no `__toString`: string interpolation and `(string)` casts
 *   are fatal errors, never a silent secret.
 * - Cloning throws — a copy would be a second delivery.
 * - The constructor parameter carries `#[SensitiveParameter]`, so stack
 *   traces and exception context redact it.
 *
 * The value leaves through exactly ONE accessor: reveal(), which returns
 * the plaintext once, drops it from memory, and throws on every later call.
 * The TTY print-once and reveal-once rules of D7 become structural. hash()
 * exposes the sha256 — the intended at-rest form — any number of times; a
 * hash is not a secret.
 *
 * What this class cannot enforce: a consumer that assigns
 * `$carrier->reveal()` to a variable owns that copy, and reflection is
 * NOT an egress boundary — `ReflectionProperty` on the class-level store
 * can recover an unrevealed plaintext, because no in-memory design
 * resists reflection. The carrier makes ACCIDENTAL egress
 * (serialize/json/dump/export) structurally impossible, not deliberate
 * egress.
 *
 * Delivery shapes (PRD 1.6, later releases) wrap this class rather than
 * routing around it; it stays final and metadata-free so they can.
 */
final class MintedSecret implements JsonSerializable
{
    /**
     * @var WeakMap<self, string>|null
     */
    private static ?WeakMap $plaintexts = null;

    private readonly string $hash;

    private bool $revealed = false;

    public function __construct(#[SensitiveParameter] string $plaintext)
    {
        $this->hash = hash('sha256', $plaintext);

        self::$plaintexts ??= new WeakMap;
        self::$plaintexts[$this] = $plaintext;
    }

    /**
     * The single point of egress: returns the plaintext ONCE and drops it
     * from memory. Every later call throws — one carrier, one delivery.
     */
    public function reveal(): string
    {
        if ($this->revealed || self::$plaintexts === null || ! self::$plaintexts->offsetExists($this)) {
            throw new LogicException('This minted secret has already been revealed: one carrier, one delivery.');
        }

        $plaintext = self::$plaintexts[$this];

        unset(self::$plaintexts[$this]);
        $this->revealed = true;

        return $plaintext;
    }

    public function revealed(): bool
    {
        return $this->revealed;
    }

    /**
     * The sha256 of the plaintext — the intended at-rest form. Not a
     * secret; callable any number of times, before or after reveal().
     */
    public function hash(): string
    {
        return $this->hash;
    }

    /**
     * @return array<string, mixed>
     */
    public function __serialize(): array
    {
        throw new LogicException('A minted secret never serializes.');
    }

    /**
     * @return list<string>
     */
    public function __sleep(): array
    {
        throw new LogicException('A minted secret never serializes.');
    }

    public function jsonSerialize(): never
    {
        throw new LogicException('A minted secret never JSON-encodes.');
    }

    public function __clone()
    {
        throw new LogicException('A minted secret never clones: one carrier, one delivery.');
    }
}
