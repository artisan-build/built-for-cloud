<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\Exceptions\RewrapInProgress;
use ArtisanBuild\BuiltForCloud\Exceptions\SigningRootRefused;
use ArtisanBuild\BuiltForCloud\Hmac\SigningRootLifecycle;

final class SigningRootEnsureCommand extends SystemAuthorityCommand
{
    protected $signature = 'bfc:signing-root:ensure
        {--local : Run against the local database, zero Cloud dependency}';

    protected $description = 'Ensure the installation signing root exists without exporting its key material';

    public function handle(SigningRootLifecycle $lifecycle): int
    {
        if (! (bool) $this->option('local')) {
            $this->error('This verb is local-only and has no HTTP equivalent. Pass --local to ensure this installation.');

            return self::FAILURE;
        }

        try {
            $lifecycle->ensure(AuditActor::cliOperator());
        } catch (SigningRootRefused|RewrapInProgress $refused) {
            $this->error($refused->getMessage());

            return self::FAILURE;
        }

        $this->line('Installation signing root is present. No secret was exported.');

        return self::SUCCESS;
    }
}
