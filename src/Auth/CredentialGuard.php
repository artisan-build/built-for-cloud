<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Auth;

use ArtisanBuild\BuiltForCloud\Console\DelegatedActor;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialAuthenticator;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\CredentialUsageRecorder;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use Throwable;

/**
 * The one guard (driver `bfc`): authenticates requests against the unified
 * credential store via per-kind strategies, and enforces the session/token
 * precedence matrix:
 *
 * - Token-guarded routes reject session-only callers — this guard never falls
 *   back to a session.
 * - On token routes the credential principal and its abilities are
 *   authoritative; a simultaneously present session neither adds nor widens
 *   anything.
 * - A request carrying both a session user and a user-bound credential bound
 *   to a DIFFERENT user is rejected, never silently resolved to either.
 * - Session-guarded routes never reach this guard, so a bearer riding along
 *   on one is never consumed and never stamps usage.
 *
 * A DELEGATED ACTOR IS NEVER THE OTHER HALF OF A MISMATCH. The mismatch
 * check below compares a credential's `user_id` — a stringified HOST-APP
 * user id — against the session principal, and a {@see DelegatedActor} is
 * a different principal TYPE whose identifier is type-qualified
 * (`bfc-console:{id}`) precisely so it can never equal one. Comparing them
 * could therefore only ever produce a FALSE mismatch — a token route
 * refusing a perfectly good credential because its holder happens to also
 * be a delegated principal — so {@see sessionUser()} excludes it
 * explicitly. Every previously shipped cell of the matrix is unchanged.
 *
 * AND NO CREDENTIAL RESOLVES A DELEGATED ACTOR. The `bfc-console:`
 * namespace is RESERVED: {@see resolveBoundUser()} refuses a `user_id`
 * inside it before any user provider is asked, refuses a delegated actor
 * if one came back anyway, and requires the resolved principal to emit
 * exactly the identifier that was stored. The first of those is the one
 * that matters — handing `bfc-console:1` to an Eloquent provider over an
 * integer key is a driver-defined coercion, not a lookup that safely
 * fails.
 *
 * The guard NEVER consults `built-for-cloud.fallback_token` or any other env
 * pseudo-credential — there is no code path from here to it. All rejections
 * are indistinguishable 401s: expired, revoked, pending, wrong-purpose and
 * unknown secrets produce the same response.
 */
final class CredentialGuard implements Guard
{
    private ?Authenticatable $user = null;

    private ?Credential $credential = null;

    private ?Credential $resolvedCredential = null;

    private bool $resolutionAttempted = false;

    private bool $authenticationAttempted = false;

    private ?Request $resolvedFor = null;

    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct(
        private readonly Container $app,
        private readonly string $name,
        private readonly array $config,
        private readonly CredentialResolver $resolver,
    ) {}

    public function check(): bool
    {
        return $this->user() !== null;
    }

    public function guest(): bool
    {
        return ! $this->check();
    }

    public function user(): ?Authenticatable
    {
        $request = $this->request();
        $this->resetForRequest($request);

        if ($this->authenticationAttempted && ! $this->resolutionAttempted) {
            // A principal explicitly supplied through Guard::setUser() keeps
            // the framework contract; no credential purpose exists to check.
            return $this->user;
        }

        $credential = $this->credentialForPurposes([
            CredentialPurpose::Consumption,
            CredentialPurpose::SystemDeployment,
        ]);

        return $credential === null ? null : $this->user;
    }

    /**
     * Resolve once for this request, but authorize the resolved row against
     * every caller's own protocol-purpose set.
     *
     * @param  list<CredentialPurpose>  $purposes
     */
    public function credentialForPurposes(array $purposes): ?Credential
    {
        $request = $this->request();
        $this->resetForRequest($request);

        if ($this->authenticationAttempted && ! $this->resolutionAttempted) {
            // setUser() published a principal without authenticating a
            // credential, matching the Guard contract's existing behavior.
            return null;
        }

        if (! $this->resolutionAttempted) {
            $this->resolutionAttempted = true;
            $this->resolvedCredential = $this->resolveCredential($request);
        }

        // Full account containment (PRD 1.15, SEC-V3-04) needs no check
        // here: the resolver itself refuses an offboarded principal —
        // {@see CredentialResolver}, the containment choke point — so an
        // offboarded subject, or a credential bound to a deactivated
        // user, never resolves in the first place, indistinguishably from
        // an unknown secret.
        $credential = $this->resolvedCredential;

        if ($credential === null || ! in_array($credential->purpose, $purposes, true)) {
            return null;
        }

        if ($this->authenticationAttempted) {
            return $this->credential;
        }

        $this->authenticationAttempted = true;

        try {
            $sessionUser = $this->sessionUser();
        } catch (Throwable) {
            // Session-user resolution FAILED (as opposed to no session guard
            // being configured). Proceeding would silently skip the
            // mismatched-principals rejection, so fail closed: the request
            // does not authenticate.
            return null;
        }

        if ($credential->user_id !== null
            && $sessionUser !== null
            && (string) $sessionUser->getAuthIdentifier() !== $credential->user_id) {
            // Mismatched simultaneous principals: reject, never pick one.
            return null;
        }

        $principal = $credential->user_id === null
            ? $credential
            : $this->resolveBoundUser($credential);

        if ($principal === null) {
            // User-bound credential whose user no longer resolves.
            return null;
        }

        if (! $this->declaration()->authorize($credential, null, $request)) {
            throw new AuthorizationException('This credential is not authorized.');
        }

        // Presenting a valid secret is a use; record only on full
        // acceptance — and the recorder answers whether the authentication
        // STANDS (SEC-2): a row revoked or expired between the resolving
        // read and the usage write fails here. A FIRST use is the burn
        // point for `first_use` declarations whose durables live in this
        // store: the linked claim code is consumed in the same transaction.
        if (! app(CredentialUsageRecorder::class)->recordUsage($credential)) {
            return null;
        }

        $this->credential = $credential;
        $this->user = $principal;

        return $this->credential;
    }

    public function id(): int|string|null
    {
        return $this->user()?->getAuthIdentifier();
    }

    /**
     * @param  array<string, mixed>  $credentials
     */
    public function validate(array $credentials = []): bool
    {
        $secret = $credentials['secret'] ?? null;

        if (! is_string($secret)) {
            return false;
        }

        $purposes = [CredentialPurpose::Consumption, CredentialPurpose::SystemDeployment];
        $bearer = $this->resolver->resolve(CredentialKind::Bearer, $secret);

        if ($bearer !== null && in_array($bearer->purpose, $purposes, true)) {
            return true;
        }

        $basic = $this->resolver->resolve(CredentialKind::Basic, $secret);

        return $basic !== null && in_array($basic->purpose, $purposes, true);
    }

    public function hasUser(): bool
    {
        $this->resetForRequest($this->request());

        return $this->user !== null;
    }

    /**
     * @return $this
     */
    public function setUser(Authenticatable $user): self
    {
        $this->resetForRequest($this->request());
        $this->user = $user;
        $this->authenticationAttempted = true;

        return $this;
    }

    /**
     * The credential that authenticated the current request, if any.
     */
    public function credential(): ?Credential
    {
        return $this->credentialForPurposes([
            CredentialPurpose::Consumption,
            CredentialPurpose::SystemDeployment,
        ]);
    }

    /**
     * The AuthManager reuses guard instances in long-lived workers. Every
     * cache in this guard is request-local and must turn over together.
     */
    private function resetForRequest(Request $request): void
    {
        if ($this->resolvedFor === $request) {
            return;
        }

        $this->user = null;
        $this->credential = null;
        $this->resolvedCredential = null;
        $this->resolutionAttempted = false;
        $this->authenticationAttempted = false;
        $this->resolvedFor = $request;
    }

    private function resolveCredential(Request $request): ?Credential
    {
        /** @var list<CredentialAuthenticator> $authenticators */
        $authenticators = [
            new BearerAuthenticator($this->resolver),
            new BasicAuthenticator($this->resolver),
        ];

        foreach ($authenticators as $authenticator) {
            $credential = $authenticator->credential($request);

            if ($credential !== null) {
                return $credential;
            }
        }

        return null;
    }

    /**
     * The user the app's session guard would see for this request, used only
     * to detect mismatched simultaneous principals. The STRUCTURAL cases —
     * no session guard named, a self-referential name, a name with no guard
     * configured — mean "no session user" and return null. A configured
     * guard that THROWS during resolution is a different state: the caller
     * must treat it as a failed lookup and reject, never as an absent
     * session, so the exception propagates.
     *
     * A DELEGATED ACTOR is excluded, and that is a fourth structural case
     * rather than a policy choice. A principal of that type is not a
     * canonical package user: its identifier is type-qualified so that it
     * can never equal a credential's `user_id`, which means every
     * comparison against one would mismatch and every token route would
     * 401 for anyone simultaneously carrying one. "Not a comparable local
     * principal" is therefore the same answer as "no session user" here.
     */
    private function sessionUser(): ?Authenticatable
    {
        $guard = config('built-for-cloud.credentials.session_guard') ?? config('auth.defaults.guard');

        if (! is_string($guard) || $guard === '' || $guard === $this->name) {
            return null;
        }

        if (! is_array(config('auth.guards.'.$guard))) {
            return null;
        }

        $user = $this->auth()->guard($guard)->user();

        return $user instanceof DelegatedActor ? null : $user;
    }

    /**
     * The canonical package user a credential is bound to, or null.
     *
     * THE RESERVED NAMESPACE NEVER REACHES A USER PROVIDER. A stored
     * `user_id` of `bfc-console:1` is refused here, before any provider
     * is asked, because what happens next is not this package's to
     * decide: handed to an Eloquent provider over an integer key, MySQL
     * coerces the non-numeric string toward `0` and can resolve the row
     * with key 0, while PostgreSQL raises. "No credential can resolve a
     * delegated actor" therefore has to be enforced on the way IN, not
     * hoped for from the driver — and the check is deliberately broad,
     * prefix-shaped and not well-formedness-shaped, because
     * `bfc-console:1junk` names no actor and must still never be handed
     * to a provider whose own coercion decides what it means.
     *
     * A returned {@see DelegatedActor} is rejected too. That is
     * unreachable through the namespace check above, and it is the
     * point: if a future app pointed the `bfc` guard's provider at the
     * delegated actors, the credential path still refuses to resolve one.
     *
     * The identifier round trip must be EXACT. A provider that answers
     * with a principal whose own identifier is not the string we asked
     * for has coerced something — a numeric string to an int, a `1junk`
     * to a `1` — and a principal reached by coercion is a principal
     * nobody bound this credential to.
     */
    private function resolveBoundUser(Credential $credential): ?Authenticatable
    {
        $userId = $credential->user_id;

        if ($userId === null || DelegatedActor::isReservedIdentifier($userId)) {
            return null;
        }

        $provider = $this->userProvider();

        if ($provider === null) {
            return null;
        }

        $user = $provider->retrieveById($userId);

        if ($user === null || $this->isDelegatedActor($user)) {
            return null;
        }

        return hash_equals((string) $user->getAuthIdentifier(), $userId) ? $user : null;
    }

    /**
     * A one-line helper rather than an inline `instanceof` because
     * static analysis narrows a user provider's return to the
     * application's CONFIGURED auth model, which makes the inline check
     * look impossible and would delete the defence.
     */
    private function isDelegatedActor(Authenticatable $user): bool
    {
        return $user instanceof DelegatedActor;
    }

    private function userProvider(): ?UserProvider
    {
        $provider = $this->config['provider'] ?? null;

        return $this->auth()->createUserProvider(is_string($provider) ? $provider : null);
    }

    private function declaration(): CredentialDeclaration
    {
        /** @var CredentialDeclaration */
        return $this->app->make(CredentialDeclaration::class);
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
