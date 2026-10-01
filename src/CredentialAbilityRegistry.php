<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use InvalidArgumentException;

/**
 * The consuming application's credential ability vocabulary.
 *
 * Resolve this singleton in an application service provider and register
 * every app-owned name there. Re-registering a name is an idempotent no-op.
 */
class CredentialAbilityRegistry
{
    /** @var array<string, true> */
    protected array $abilities = [];

    public function register(string ...$abilities): void
    {
        foreach ($abilities as $ability) {
            $this->assertValidRegistration($ability);
        }

        foreach ($abilities as $ability) {
            $this->abilities[$ability] = true;
        }
    }

    public function has(string $ability): bool
    {
        return isset($this->abilities[$ability]);
    }

    /** @return list<string> */
    public function all(): array
    {
        return array_keys($this->abilities);
    }

    private function assertValidRegistration(string $ability): void
    {
        if (OperatorAbility::tryFrom($ability) !== null) {
            throw new InvalidArgumentException(
                sprintf('App credential ability "%s" collides with the OperatorAbility vocabulary.', $ability),
            );
        }

        if (preg_match('/^[a-z][a-z0-9-]*\.[a-z][a-z0-9_.-]*$/D', $ability) !== 1
            || in_array('', explode('.', $ability), true)) {
            throw new InvalidArgumentException(
                sprintf('Invalid app credential ability "%s".', $ability),
            );
        }
    }
}
