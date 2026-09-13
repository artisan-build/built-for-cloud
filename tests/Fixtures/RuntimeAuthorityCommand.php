<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Commands\SystemAuthorityCommand;
use Illuminate\Contracts\Auth\Factory as AuthFactory;

final class RuntimeAuthorityCommand extends SystemAuthorityCommand
{
    protected $signature = 'fixture:runtime-authority {shape} {user}';

    public function handle(RuntimeHumanAuthenticator $authenticator, AuthFactory $auth): int
    {
        $authenticator->run((string) $this->argument('shape'), (string) $this->argument('user'), $auth);

        return self::SUCCESS;
    }
}
