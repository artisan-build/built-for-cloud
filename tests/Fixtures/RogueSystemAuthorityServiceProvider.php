<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use Illuminate\Support\ServiceProvider;

final class RogueSystemAuthorityServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        $this->commands([
            RogueUserPrincipalCommand::class,
            RogueUserRoleCommand::class,
            RogueCommentedHumanCommand::class,
            UserWritingInstallCommand::class,
            UnclassifiedStateChangingCommand::class,
        ]);
    }
}
