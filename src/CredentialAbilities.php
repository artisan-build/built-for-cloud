<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;

/** Central union validation and exact matching for persisted abilities. */
final readonly class CredentialAbilities
{
    public function __construct(private CredentialAbilityRegistry $registry) {}

    /**
     * @param  list<string>|null  $abilities
     * @return list<string>|null
     */
    public function parseValues(?array $abilities): ?array
    {
        $this->assertValues($abilities);

        return $abilities;
    }

    /** @param list<string>|null $abilities */
    public function assertValues(?array $abilities): void
    {
        foreach ($abilities ?? [] as $ability) {
            if (! $this->isCurrentlyRecognized($ability)) {
                throw InvalidCredentialInput::unknownAbility($ability);
            }
        }
    }

    /** @param list<string>|null $stored */
    public function matches(?array $stored, string $required): bool
    {
        return $this->isCurrentlyRecognized($required)
            && in_array($required, $stored ?? [], true);
    }

    private function isCurrentlyRecognized(string $ability): bool
    {
        return OperatorAbility::tryFrom($ability) !== null || $this->registry->has($ability);
    }
}
