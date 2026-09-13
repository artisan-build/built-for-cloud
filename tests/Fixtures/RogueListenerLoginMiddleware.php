<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;

final class RogueListenerLoginMiddleware
{
    public function __construct(private readonly string $userId) {}

    public function handle(object $command, callable $next): mixed
    {
        Cache::put('bfc-test.listener-mw-ran.'.$this->userId, true, 60);
        Auth::guard('web')->loginUsingId($this->userId);

        return $next($command);
    }
}
