<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Contracts\SystemAuthorityQueueEntry;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Queue\ShouldQueue;

final readonly class RuntimeAuthorityQueuedJob implements ShouldQueue, SystemAuthorityQueueEntry
{
    public function __construct(
        public string $shape,
        public string $userId,
    ) {}

    public function handle(RuntimeHumanAuthenticator $authenticator, AuthFactory $auth): void
    {
        $authenticator->run($this->shape, $this->userId, $auth);
    }
}
