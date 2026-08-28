<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use Carbon\CarbonInterface;

/**
 * What a caller may choose when rotating a unified-store credential
 * (PRD 1.7, D6). The default is TOTAL PRESERVATION: the replacement carries
 * the exact ability set, subject binding and remaining expiry of the row it
 * replaces, and nothing here can change that silently.
 *
 * - `emergency` collapses the grace window: the old row dies immediately
 *   instead of staying resolvable for the hour.
 * - `override` is the explicit authorization request for a changed
 *   replacement (D6 point 4). The changed dimensions are tracked by
 *   PRESENCE (`abilitiesProvided` / `expiryProvided`), separately from
 *   their values, because "explicitly none" is a real override: an
 *   expiry provided as null overrides a finite expiry to NO expiry, and
 *   abilities provided empty narrow to NO abilities. An ABSENT dimension
 *   always means "preserve the source's". Any provided dimension without
 *   the flag — widening or narrowing alike — is refused, and the flag
 *   with nothing provided is refused too.
 * - `codeTtlSeconds` applies only when rotating an `asymmetric` credential,
 *   whose replacement is delivered as a fresh enrollment code (the claim
 *   primitive's required 60s–7d lifetime, PRD 1.1).
 *
 * Both transports construct this through {@see fromInput()}, where
 * presence means key-presence in the input array: the HTTP transport's
 * `$request->only()` keeps an explicit JSON null and drops an absent
 * field, and the CLI includes a key exactly when its option (or its
 * `--clear-*` form) was passed. The value normalization is literally
 * {@see MintOptions::fromInput()}, so rotate rejects exactly the junk mint
 * rejects, with the same messages.
 */
final readonly class RotateOptions
{
    /**
     * @param  list<string>|null  $abilities
     */
    public function __construct(
        public bool $emergency = false,
        public bool $override = false,
        public bool $abilitiesProvided = false,
        public ?array $abilities = null,
        public bool $expiryProvided = false,
        public ?CarbonInterface $expiresAt = null,
        public ?int $codeTtlSeconds = null,
    ) {}

    /**
     * @param  array<string, mixed>  $input
     */
    public static function fromInput(array $input): self
    {
        $normalized = MintOptions::fromInput([
            'abilities' => $input['abilities'] ?? null,
            'expires_at' => $input['expires_at'] ?? null,
            'code_ttl_seconds' => $input['code_ttl_seconds'] ?? null,
        ]);

        return new self(
            emergency: self::boolFrom($input['emergency'] ?? null, 'emergency'),
            override: self::boolFrom($input['override'] ?? null, 'override'),
            abilitiesProvided: array_key_exists('abilities', $input),
            abilities: $normalized->abilities,
            expiryProvided: array_key_exists('expires_at', $input),
            expiresAt: $normalized->expiresAt,
            codeTtlSeconds: $normalized->codeTtlSeconds,
        );
    }

    /**
     * Whether the caller asked for a replacement DIFFERENT from the source
     * — the thing that requires (and, with nothing provided, forbids) the
     * override flag. Presence, not value comparison: providing the current
     * abilities back without the flag is still refused, deliberately —
     * "this input changes nothing today" is a race, not a contract.
     */
    public function requestsChange(): bool
    {
        return $this->abilitiesProvided || $this->expiryProvided;
    }

    /**
     * The requested delta, for the override's own authorization and its
     * audit note.
     */
    public function overrideDelta(): RotationOverride
    {
        return new RotationOverride(
            changesAbilities: $this->abilitiesProvided,
            abilities: $this->abilities,
            changesExpiry: $this->expiryProvided,
            expiresAt: $this->expiresAt,
        );
    }

    private static function boolFrom(mixed $value, string $flag): bool
    {
        if ($value === null) {
            return false;
        }

        if (is_bool($value)) {
            return $value;
        }

        $parsed = is_scalar($value)
            ? filter_var($value, FILTER_VALIDATE_BOOL, FILTER_NULL_ON_FAILURE)
            : null;

        if ($parsed === null) {
            throw InvalidCredentialInput::nonBooleanFlag($flag);
        }

        return $parsed;
    }
}
