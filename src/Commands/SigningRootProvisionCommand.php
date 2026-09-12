<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Commands;

use ArtisanBuild\BuiltForCloud\Commands\Concerns\ParsesCredentialVerbInput;
use ArtisanBuild\BuiltForCloud\Exceptions\SigningRootRefused;
use ArtisanBuild\BuiltForCloud\Hmac\SigningRootLifecycle;
use Illuminate\Console\Command;

final class SigningRootProvisionCommand extends Command
{
    use ParsesCredentialVerbInput;

    protected $signature = 'bfc:signing-root:provision
        {--local : Run against the local database, zero Cloud dependency}';

    protected $description = 'Provision the installation signing root without exporting its key material';

    public function handle(SigningRootLifecycle $lifecycle): int
    {
        if (! $this->requireLocal()) {
            return self::FAILURE;
        }

        try {
            $result = $lifecycle->provision();
        } catch (SigningRootRefused $refused) {
            $this->error($refused->getMessage());

            return self::FAILURE;
        }

        $this->line('Provisioned signing root '.$result->summary->id.'.');

        return self::SUCCESS;
    }
}
