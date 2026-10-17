<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\Exceptions\DelegatedPrincipalUnsupported;
use ArtisanBuild\BuiltForCloud\Exceptions\NoActingPrincipal;
use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;

/**
 * The single acting principal: ONE value, read by the principal and the
 * audit stream alike.
 *
 * THIS CLASS MUTATES NOTHING — and that is a claim about this class, not
 * about the request. It only ever READS.
 *
 * WHAT IT READS. A verified MCP request assertion is read from
 * {@see RequestAssertion}, which the MCP middleware published before
 * anything behind it ran. Without one, the supplied request's own user
 * resolver is authoritative: it carries either a direct credential, the
 * applicable guard's local session user, or nobody.
 *
 * PRECEDENCE — delegated wins, and there is no union. A verified
 * request assertion wins over any request principal; without one, the
 * request resolver's principal is returned unchanged.
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

    private mixed $resolvedRequestPrincipal = null;

    private bool $resolvedRequestPrincipalSet = false;

    public function __construct(private readonly Container $app) {}

    /**
     * The acting principal for the CURRENT request. Repeated calls
     * within one request return the identical instance.
     */
    public function resolve(): ActingPrincipal
    {
        return $this->acting($this->request());
    }

    /**
     * The one answer to who is acting on the supplied request. A verified
     * assertion wins; otherwise the supplied request's own user resolver is
     * authoritative for both direct credentials and local sessions.
     */
    public function acting(Request $request): ActingPrincipal
    {
        $applicable = $this->applicableGuardName();
        $requestAssertion = RequestAssertion::principal($request);
        $requestPrincipal = $requestAssertion instanceof ActingPrincipal
            ? null
            : $this->requestPrincipal($request);

        return $this->actingFromSources($request, $applicable, $requestAssertion, $requestPrincipal);
    }

    private function actingFromSources(
        Request $request,
        ?string $applicable,
        ?ActingPrincipal $requestAssertion,
        mixed $requestPrincipal,
    ): ActingPrincipal {

        if ($this->resolvedFor !== $request
            || $this->resolvedUnder !== $applicable
            || $this->resolvedRequestAssertion !== $requestAssertion
            || ! $this->resolvedRequestPrincipalSet
            || $this->resolvedRequestPrincipal !== $requestPrincipal) {
            $this->resolved = null;
            $this->resolvedFor = $request;
            $this->resolvedUnder = $applicable;
            $this->resolvedRequestAssertion = $requestAssertion;
            $this->resolvedRequestPrincipal = $requestPrincipal;
            $this->resolvedRequestPrincipalSet = true;
        }

        return $this->resolved ??= $this->resolveNow($requestAssertion, $requestPrincipal, $applicable);
    }

    /**
     * Resolve the host application's local user row when the acting source
     * has one. A verified delegated actor never aliases a local user.
     */
    public function localUser(Request $request): ?Authenticatable
    {
        $acting = $this->acting($request);

        if ($acting->delegated || $acting->principal instanceof DelegatedActor) {
            return null;
        }

        $principal = $acting->principal;

        if (! $principal instanceof Credential) {
            return $principal;
        }

        $userId = $principal->user_id;

        if ($userId === null || DelegatedActor::isReservedIdentifier($userId)) {
            return null;
        }

        $provider = $this->localUserProvider($acting->guard);
        $user = $provider?->retrieveById($userId);

        if ($user === null || $this->isDelegatedActor($user)) {
            return null;
        }

        return hash_equals((string) $user->getAuthIdentifier(), $userId) ? $user : null;
    }

    /**
     * @throws DelegatedPrincipalUnsupported
     * @throws NoActingPrincipal
     */
    public function require(Request $request): ActingPrincipal
    {
        $applicable = $this->applicableGuardName();
        $requestAssertion = RequestAssertion::principal($request);
        $requestPrincipal = $requestAssertion instanceof ActingPrincipal
            ? null
            : $this->requestPrincipal($request);

        if (! $requestAssertion instanceof ActingPrincipal
            && $requestPrincipal instanceof DelegatedActor) {
            throw new DelegatedPrincipalUnsupported('A delegated actor must come from a verified request assertion.');
        }

        $acting = $this->actingFromSources($request, $applicable, $requestAssertion, $requestPrincipal);

        if (! $acting->check()) {
            throw new NoActingPrincipal('No acting principal is available for this request.');
        }

        return $acting;
    }

    private function resolveNow(
        ?ActingPrincipal $requestAssertion,
        mixed $requestPrincipal,
        ?string $applicableGuard,
    ): ActingPrincipal {
        // A verified assertion is the delegated principal for this request,
        // ahead of any request user or local session and never unioned with it.
        if ($requestAssertion instanceof ActingPrincipal) {
            return $requestAssertion;
        }

        // A bare delegated actor has no verified claims. acting() never
        // throws, so it resolves to nobody; require() names the unsupported
        // delegated source structurally.
        if (! $requestPrincipal instanceof Authenticatable || $requestPrincipal instanceof DelegatedActor) {
            return ActingPrincipal::none();
        }

        return ActingPrincipal::local(
            $requestPrincipal instanceof Credential ? null : $applicableGuard,
            $requestPrincipal,
        );
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

    private function requestPrincipal(Request $request): mixed
    {
        return ($request->getUserResolver())();
    }

    private function localUserProvider(?string $guard): ?UserProvider
    {
        $guardConfig = $guard === null ? null : config('auth.guards.'.$guard);
        $provider = is_array($guardConfig) ? ($guardConfig['provider'] ?? null) : null;

        return $this->auth()->createUserProvider(is_string($provider) ? $provider : 'users');
    }

    /**
     * Keep this check behind a method because a configured user provider's
     * static return type can otherwise make the defensive branch look
     * impossible to static analysis.
     */
    private function isDelegatedActor(Authenticatable $user): bool
    {
        return $user instanceof DelegatedActor;
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
