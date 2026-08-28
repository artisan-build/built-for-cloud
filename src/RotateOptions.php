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
 * - `override` is the explicit authorization for a changed replacement
 *   (D6 point 4): `abilities` / `expiresAt` are consumed ONLY under it, the
 *   verb matrix is consulted again with the override visible in context,
 *   and the audit row records the reason and the delta. Any of the three
 *   present without the flag — widening or narrowing alike — is refused.
 * - `codeTtlSeconds` applies only when rotating an `asymmetric` credential,
 *   whose replacement is delivered as a fresh enrollment code (the claim
 *   primitive's required 60s–7d lifetime, PRD 1.1).
 *
 * Both transports construct this through {@see fromInput()}; the value
 * normalization is literally {@see MintOptions::fromInput()}, so rotate
 * rejects exactly the junk mint rejects, with the same messages.
 */
final readonly class RotateOptions
{
    /**
     * @param  list<string>|null  $abilities
     */
    public function __construct(
        public bool $emergency = false,
        public bool $override = false,
        public ?array $abilities = null,
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
            abilities: $normalized->abilities,
            expiresAt: $normalized->expiresAt,
            codeTtlSeconds: $normalized->codeTtlSeconds,
        );
    }

    /**
     * Whether the caller asked for a replacement DIFFERENT from the source
     * — the thing that requires (and, with nothing present, forbids) the
     * override flag. Presence, not value comparison: passing the current
     * abilities back without the flag is still refused, deliberately —
     * "this input changes nothing today" is a race, not a contract.
     */
    public function requestsChange(): bool
    {
        return $this->abilities !== null || $this->expiresAt !== null;
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
