<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Support\Facades\Auth;

final readonly class HostRuntimeAuthQueuedJob implements ShouldQueue
{
    public function __construct(public string $userId) {}

    public function handle(RuntimeHumanAuthenticator $authenticator, AuthFactory $auth): void
    {
        $authenticator->run('facade-login', $this->userId, $auth);
        config()->set('runtime-authority.host-job-user', Auth::id());
    }
}
