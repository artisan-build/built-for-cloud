<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Listeners;

use ArtisanBuild\BuiltForCloud\Exceptions\SystemAuthorityViolation;
use ArtisanBuild\BuiltForCloud\SystemAuthorityContext;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\SessionGuard;
use Illuminate\Contracts\Auth\Factory;
use Throwable;

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

        // Clearing state is best-effort and MUST NOT decide whether we refuse. The
        // event's guard name may not resolve, and a guard that is not a SessionGuard
        // has no session or recaller to clear — neither is a reason to let the
        // authentication stand, and the published bound is stated over any guard that
        // dispatches these events rather than over SessionGuard.
        try {
            $guard = $this->auth->guard($event->guard);

            if ($guard instanceof SessionGuard) {
                $guard->getSession()->remove($guard->getName());
                $guard->getCookieJar()->unqueue($guard->getRecallerName());
                $guard->forgetUser();
            } elseif (method_exists($guard, 'forgetUser')) {
                $guard->forgetUser();
            }
        } catch (Throwable) {
            // Fall through to the refusal.
        }

        throw SystemAuthorityViolation::humanAuthentication();
    }
}
