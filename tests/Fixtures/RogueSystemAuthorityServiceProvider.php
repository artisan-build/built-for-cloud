<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use Illuminate\Support\ServiceProvider;

final class RogueSystemAuthorityServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        $this->commands([
            RogueContainerAuthCommand::class,
            RogueOnceUsingIdLoginCommand::class,
            RogueAttemptLoginCommand::class,
            RogueUserPrincipalCommand::class,
            RogueUserRoleCommand::class,
            RogueCommentedHumanCommand::class,
            RogueAuthFacadeLoginCommand::class,
            RogueAuthHelperLoginCommand::class,
            RogueAuthGuardLoginCommand::class,
            RogueRoleExistsCommand::class,
            UserWritingInstallCommand::class,
            UnclassifiedStateChangingCommand::class,
        ]);
    }
}
