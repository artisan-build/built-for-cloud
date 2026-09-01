<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Listeners;

use ArtisanBuild\BuiltForCloud\Console\ConsoleGuard;
use ArtisanBuild\BuiltForCloud\Console\ConsoleGuardConfiguration;
use ArtisanBuild\BuiltForCloud\Console\ConsoleSession;
use Illuminate\Auth\AuthManager;
use Illuminate\Auth\Events\Login;
use Illuminate\Contracts\Session\Session;

final readonly class EvictConsolePrincipal
{
    public function __construct(
        private AuthManager $auth,
        private Session $session,
    ) {}

    public function handle(Login $event): void
    {
        // Console redemption fires this event too. Its new principal is
        // the one that must survive, not the one this listener evicts.
        if ($event->guard === ConsoleGuardConfiguration::GUARD) {
            return;
        }

        $guard = $this->auth->guard(ConsoleGuardConfiguration::GUARD);

        if (! $guard instanceof ConsoleGuard) {
            return;
        }

        foreach (ConsoleSession::keys() as $key) {
            $this->session->forget($key);
        }

        $this->session->forget($guard->getName());
        $this->auth->forgetGuards();
    }
}
