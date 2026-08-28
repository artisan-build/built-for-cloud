<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Carbon\CarbonInterface;

/**
 * The delta a rotation override requests (PRD 1.7, D6 point 4) — what the
 * declaration's {@see Contracts\AuthorizesRotationOverrides} hook is asked
 * to authorize, and what the audit note records.
 *
 * PRESENCE is the signal, tracked separately from the values, because
 * "explicitly none" is a real override on both dimensions: `changesExpiry`
 * with a null `expiresAt` overrides a finite expiry to NO expiry, and
 * `changesAbilities` with null `abilities` narrows to NO abilities (the
 * store's one canonical empty — it grants nothing). A dimension whose
 * flag is false is preserved from the source row exactly, and its value
 * here is meaningless.
 */
final readonly class RotationOverride
{
    /**
     * @param  list<string>|null  $abilities
     */
    public function __construct(
        public bool $changesAbilities,
        public ?array $abilities,
        public bool $changesExpiry,
        public ?CarbonInterface $expiresAt,
    ) {}
}
