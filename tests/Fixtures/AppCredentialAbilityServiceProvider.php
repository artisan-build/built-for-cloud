<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\CredentialAbilityRegistry;
use Illuminate\Support\ServiceProvider;

final class AppCredentialAbilityServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->make(CredentialAbilityRegistry::class)->register(
            'assay.usage',
            'assay.content',
        );
    }
}
