<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use Illuminate\Auth\Events\Authenticated;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Events\Dispatcher;

/**
 * A guard that is NOT a SessionGuard but does dispatch Laravel's authentication
 * events. The published bound is stated over "a guard that dispatches
 * `Authenticated` or `Login`", not over `SessionGuard`, so that wording needs an
 * executed control rather than an inference from the one guard the other controls
 * happen to use.
 */
final class RogueEventDispatchingGuard implements Guard
{
    private ?Authenticatable $user = null;

    public function __construct(private readonly Dispatcher $events) {}

    public function check(): bool
    {
        return $this->user instanceof Authenticatable;
    }

    public function guest(): bool
    {
        return ! $this->check();
    }

    public function user(): ?Authenticatable
    {
        return $this->user;
    }

    public function id(): int|string|null
    {
        return $this->user?->getAuthIdentifier();
    }

    /** @param array<string, mixed> $credentials */
    public function validate(array $credentials = []): bool
    {
        return false;
    }

    public function hasUser(): bool
    {
        return $this->check();
    }

    public function setUser(Authenticatable $user): void
    {
        $this->user = $user;

        $this->events->dispatch(new Authenticated('rogue-dispatching', $user));
    }
}
