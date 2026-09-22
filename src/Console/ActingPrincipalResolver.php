<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;

/**
 * The single acting principal: ONE value, read by the principal and the
 * audit stream alike.
 *
 * THIS CLASS MUTATES NOTHING — and that is a claim about this class, not
 * about the request. It only ever READS.
 *
 * WHAT IT READS. The route's applicable guard is
 * `AuthManager::getDefaultDriver()`: whatever the app configured, or
 * whatever an `auth:<guard>` middleware just set for the request it runs
 * in. A verified MCP request assertion is read from
 * {@see RequestAssertion}, which the MCP middleware published before
 * anything behind it ran.
 *
 * PRECEDENCE — delegated wins, and there is no union. A verified
 * request assertion wins over a local principal; without one, guard
 * resolution is unchanged.
 *
 * ONE VALUE, not two equal answers. {@see resolve()} memoizes and hands
 * back the identical object to every caller. The memo is keyed on the
 * REQUEST INSTANCE — not merely set once, because this singleton
 * outlives a single request in a long-lived worker, and a principal
 * resolved for an earlier request must never leak into this one (the
 * same discipline {@see CredentialGuard} applies for the same reason) —
 * AND on the APPLICABLE GUARD, because that is what the answer is about.
 * A route's guard is established mid-request, by `auth:<guard>`, so a
 * caller running before that middleware and a caller running after it
 * are asking about two different states and must not be handed one
 * cached answer.
 *
 * CLAIMS COME FROM THIS HANDOFF. An MCP request reads the assertion that
 * middleware just verified, never the shadow row's shared
 * `last_handoff_*` copy, which a later handoff for the same subject
 * overwrites.
 */
final class ActingPrincipalResolver
{
    private ?ActingPrincipal $resolved = null;

    private ?Request $resolvedFor = null;

    private ?string $resolvedUnder = null;

    private ?ActingPrincipal $resolvedRequestAssertion = null;

    public function __construct(private readonly Container $app) {}

    /**
     * The acting principal for the CURRENT request. Repeated calls
     * within one request return the identical instance.
     */
    public function resolve(): ActingPrincipal
    {
        $request = $this->request();
        $applicable = $this->applicableGuardName();
        $requestAssertion = RequestAssertion::principal($request);

        if ($this->resolvedFor !== $request
            || $this->resolvedUnder !== $applicable
            || $this->resolvedRequestAssertion !== $requestAssertion) {
            $this->resolved = null;
            $this->resolvedFor = $request;
            $this->resolvedUnder = $applicable;
            $this->resolvedRequestAssertion = $requestAssertion;
        }

        return $this->resolved ??= $this->resolveNow($requestAssertion);
    }

    private function resolveNow(?ActingPrincipal $requestAssertion): ActingPrincipal
    {
        // A verified assertion is the delegated principal for this request,
        // ahead of any local session and never unioned with it.
        if ($requestAssertion instanceof ActingPrincipal) {
            return $requestAssertion;
        }

        $guard = $this->localGuardName();

        if ($guard === null) {
            return ActingPrincipal::none();
        }

        $user = $this->auth()->guard($guard)->user();

        // A delegated actor reached through a guard that is not this
        // package's carries no verified claims — nothing could attribute
        // or authorize from it — so it is not a local principal either.
        // The typed branch fails towards nobody.
        if ($user === null || $user instanceof DelegatedActor) {
            return ActingPrincipal::none();
        }

        return ActingPrincipal::local($guard, $user);
    }

    /**
     * The guard this ROUTE resolves through — Laravel's own default
     * driver, which `auth:<guard>` sets for the request it runs in.
     */
    private function applicableGuardName(): ?string
    {
        $guard = config('auth.defaults.guard');

        return is_string($guard) && $guard !== '' ? $guard : null;
    }

    /**
     * The applicable guard when it is the app's OWN, or null when it
     * structurally has none.
     *
     * Runtime configuration can remove or replace the package-installed
     * web guard, and asking the AuthManager for a guard that does not
     * exist throws — so structural absence is read as "nobody
     * is acting locally", the same stance {@see CredentialGuard} takes.
     * A CONFIGURED guard that throws during resolution is a different
     * state and is left to propagate.
     */
    private function localGuardName(): ?string
    {
        $guard = $this->applicableGuardName();

        return $guard === null ? null : (is_array(config('auth.guards.'.$guard)) ? $guard : null);
    }

    private function auth(): AuthManager
    {
        /** @var AuthManager */
        return $this->app->make('auth');
    }

    private function request(): Request
    {
        /** @var Request */
        return $this->app->make('request');
    }
}
