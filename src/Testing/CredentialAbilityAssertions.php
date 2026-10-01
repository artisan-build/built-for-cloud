<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use ArtisanBuild\BuiltForCloud\CredentialAbilityRegistry;
use Illuminate\Contracts\Foundation\Application;
use PHPUnit\Framework\Assert;

final class CredentialAbilityAssertions
{
    public static function assertRegistered(Application $app, string ...$abilities): void
    {
        $registry = $app->make(CredentialAbilityRegistry::class);

        foreach ($abilities as $ability) {
            Assert::assertTrue(
                $registry->has($ability),
                sprintf('Credential ability [%s] is not registered.', $ability),
            );
        }
    }
}
