<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use ArtisanBuild\BuiltForCloud\CredentialAbilities;
use ArtisanBuild\BuiltForCloud\CredentialAbilityRegistry;
use Illuminate\Contracts\Foundation\Application;

final class FakeCredentialAbilityRegistry extends CredentialAbilityRegistry
{
    public static function install(Application $app): self
    {
        $fake = new self;

        $app->instance(CredentialAbilityRegistry::class, $fake);
        $app->forgetInstance(CredentialAbilities::class);

        return $fake;
    }

    public function reset(): void
    {
        $this->abilities = [];
    }
}
