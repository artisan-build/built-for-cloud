<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Listeners;

use ArtisanBuild\BuiltForCloud\Exceptions\SystemAuthorityViolation;
use ArtisanBuild\BuiltForCloud\SystemAuthorityContext;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\SessionGuard;
use Illuminate\Contracts\Auth\Factory;

final readonly class RefuseSystemAuthorityAuthentication
{
    public function __construct(
        private SystemAuthorityContext $context,
        private Factory $auth,
    ) {}

    public function handle(Authenticated|Login $event): void
    {
        if (! $this->context->active()) {
            return;
        }

        $guard = $this->auth->guard($event->guard);

        if ($guard instanceof SessionGuard) {
            $guard->getSession()->remove($guard->getName());
            $guard->getCookieJar()->unqueue($guard->getRecallerName());
            $guard->forgetUser();
        }

        throw SystemAuthorityViolation::humanAuthentication();
    }
}
