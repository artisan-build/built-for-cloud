<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\Exceptions\RewrapInProgress;
use ArtisanBuild\BuiltForCloud\Exceptions\SigningRootRefused;
use ArtisanBuild\BuiltForCloud\Hmac\SigningRootLifecycle;

final class SigningRootProvisionCommand extends SystemAuthorityCommand
{
    protected $signature = 'bfc:signing-root:provision
        {--local : Run against the local database, zero Cloud dependency}';

    protected $description = 'Provision the installation signing root without exporting its key material';

    public function handle(SigningRootLifecycle $lifecycle): int
    {
        if (! (bool) $this->option('local')) {
            $this->error('This verb is local-only and has no HTTP equivalent. Pass --local to provision this installation.');

            return self::FAILURE;
        }

        try {
            $result = $lifecycle->provision(AuditActor::cliOperator());
        } catch (SigningRootRefused|RewrapInProgress $refused) {
            $this->error($refused->getMessage());

            return self::FAILURE;
        }

        $this->line('Provisioned installation signing root '.$result->summary->id.'. No secret was exported.');

        return self::SUCCESS;
    }
}
