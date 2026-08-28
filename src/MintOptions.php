<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use Carbon\CarbonInterface;
use Illuminate\Support\Carbon as SupportCarbon;
use Throwable;

/**
 * What a caller may choose when minting into the unified store (PRD 1.6).
 *
 * Everything here is CALLER-CHOSEN and optional. In particular `expiresAt`
 * has NO default, deliberately (PRD 1.3, DO-NOT-BUILD: TTL defaults on
 * durables): revocation-on-event, not expiry, is the intended end of a
 * durable's life, and a package that quietly stamps one would be nudging.
 *
 * `codeTtlSeconds` applies only to the `asymmetric` kind, whose delivery is
 * an enrollment code minted through the claim primitive — the code is the
 * thing with the short, REQUIRED lifetime (60s–7d, PRD 1.1), never the
 * credential.
 *
 * Both transports construct this through {@see fromInput()}, the ONE
 * normalization: junk is rejected with the same
 * {@see InvalidCredentialInput} on the CLI and over HTTP — a transport
 * that quietly coerced what the other refuses would break parity at the
 * front door.
 */
final readonly class MintOptions
{
    /**
     * The abilities input's package-enforced bounds: no credential needs
     * more distinct abilities than this, and an entry longer than this is
     * not an ability name — both are rejected, identically on both
     * transports, before anything reaches storage.
     */
    public const int MAX_ABILITIES = 32;

    public const int MAX_ABILITY_LENGTH = 128;

    /**
     * @param  list<string>|null  $abilities
     */
    public function __construct(
        public CredentialKind $kind = CredentialKind::Bearer,
        public ?string $name = null,
        public ?array $abilities = null,
        public ?CarbonInterface $expiresAt = null,
        public ?string $userId = null,
        public ?int $codeTtlSeconds = null,
    ) {}

    /**
     * The shared input normalization both transport adapters use (the CLI
     * command and the HTTP controller). Accepts each field in the shapes
     * the transports naturally carry and rejects everything else:
     *
     * - `kind`: a {@see CredentialKind} value string; absent means bearer.
     * - `abilities`: a list of ability strings OR one comma-separated
     *   string. Whitespace is trimmed, empties dropped, and **an empty
     *   result normalizes to null** — the store grants nothing for null
     *   and [] alike, so the summary always serializes the one canonical
     *   shape (null) on both transports.
     * - `expires_at`: a timestamp string or Carbon instance; absent means
     *   NO expiry (never defaulted).
     * - `code_ttl_seconds`: a whole number (int, or a digits-only
     *   string). `"60junk"` is REJECTED, never truncated to 60.
     *
     * @param  array<string, mixed>  $input
     */
    public static function fromInput(array $input): self
    {
        return new self(
            kind: self::kindFrom($input['kind'] ?? null),
            name: self::optionalString($input['name'] ?? null),
            abilities: self::abilitiesFrom($input['abilities'] ?? null),
            expiresAt: self::expiryFrom($input['expires_at'] ?? null),
            userId: self::optionalString($input['user_id'] ?? null),
            codeTtlSeconds: self::codeTtlFrom($input['code_ttl_seconds'] ?? null),
        );
    }

    private static function kindFrom(mixed $kind): CredentialKind
    {
        if ($kind === null || $kind === '') {
            return CredentialKind::Bearer;
        }

        if ($kind instanceof CredentialKind) {
            return $kind;
        }

        $parsed = is_string($kind) ? CredentialKind::tryFrom($kind) : null;

        if ($parsed === null) {
            throw InvalidCredentialInput::unknownKind(is_scalar($kind) ? (string) $kind : gettype($kind));
        }

        return $parsed;
    }

    private static function optionalString(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * @return list<string>|null
     */
    private static function abilitiesFrom(mixed $abilities): ?array
    {
        if ($abilities === null) {
            return null;
        }

        if (is_string($abilities)) {
            $abilities = explode(',', $abilities);
        }

        if (! is_array($abilities)) {
            throw InvalidCredentialInput::malformedAbilities();
        }

        $normalized = [];

        foreach ($abilities as $ability) {
            if (! is_string($ability)) {
                throw InvalidCredentialInput::malformedAbilities();
            }

            $ability = trim($ability);

            if ($ability === '') {
                continue;
            }

            if (strlen($ability) > self::MAX_ABILITY_LENGTH) {
                throw InvalidCredentialInput::abilityTooLong(self::MAX_ABILITY_LENGTH);
            }

            $normalized[] = $ability;
        }

        if (count($normalized) > self::MAX_ABILITIES) {
            throw InvalidCredentialInput::tooManyAbilities(self::MAX_ABILITIES);
        }

        // The one canonical empty: null. [] and null both grant nothing.
        return $normalized === [] ? null : $normalized;
    }

    private static function expiryFrom(mixed $expiry): ?CarbonInterface
    {
        if ($expiry === null || $expiry === '') {
            return null;
        }

        if ($expiry instanceof CarbonInterface) {
            return $expiry;
        }

        if (! is_string($expiry)) {
            throw InvalidCredentialInput::unparseableExpiry();
        }

        try {
            return SupportCarbon::parse($expiry);
        } catch (Throwable) {
            throw InvalidCredentialInput::unparseableExpiry();
        }
    }

    private static function codeTtlFrom(mixed $ttl): ?int
    {
        if ($ttl === null || $ttl === '') {
            return null;
        }

        if (is_int($ttl)) {
            return $ttl;
        }

        // A whole number only — "60junk" is junk, never 60. A NEGATIVE
        // whole number parses here so `--code-ttl=-1` on the CLI converges
        // on the same bounds error the HTTP leg's integer -1 hits, rather
        // than a different "not an integer" rejection.
        if (is_string($ttl) && preg_match('/^-?\d+$/', $ttl) === 1) {
            return (int) $ttl;
        }

        throw InvalidCredentialInput::nonIntegerCodeTtl();
    }
}
