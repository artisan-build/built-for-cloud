<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Middleware;

use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Session\Session;
use Illuminate\Http\Request;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Session\SessionManager;

final class PreventBearerUrlPersistence extends StartSession
{
    public function __construct(SessionManager $manager, CacheFactory $cache)
    {
        parent::__construct($manager, static fn (): CacheFactory => $cache);
    }

    /** @param Session $session */
    protected function storeCurrentUrl(Request $request, $session): void
    {
        $session->forget(['_previous.url', '_previous.route']);
    }
}
