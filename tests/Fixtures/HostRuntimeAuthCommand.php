<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use Illuminate\Console\Command;
use Illuminate\Contracts\Auth\Factory as AuthFactory;

final class HostRuntimeAuthCommand extends Command
{
    protected $signature = 'fixture:host-runtime-auth {user}';

    public function handle(RuntimeHumanAuthenticator $authenticator, AuthFactory $auth): int
    {
        $authenticator->run('facade-login', (string) $this->argument('user'), $auth);

        return self::SUCCESS;
    }
}
