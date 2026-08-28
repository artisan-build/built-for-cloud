<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Auth;

use ArtisanBuild\BuiltForCloud\Contracts\CredentialAuthenticator;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
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
 * RESERVED matrix row (Console fast-follow, unimplemented): a future
 * `bfc-console` delegated-session guard adds one more rule — on a request
 * carrying both a local `web` session and a delegated session, the delegated
 * guard wins for the acting principal AND for any UI/attribution branching,
 * never a union of the two. Recorded here so the decided rule survives until
 * that guard ships; nothing enforces it in this release.
 *
 * The guard NEVER consults `built-for-cloud.fallback_token` or any other env
 * pseudo-credential — there is no code path from here to it. All rejections
 * are indistinguishable 401s: expired, revoked, pending and unknown secrets
 * produce the same response.
 */
final class CredentialGuard implements Guard
{
    private ?Authenticatable $user = null;

    private ?Credential $credential = null;

    private bool $attempted = false;

    private ?Request $resolvedFor = null;

    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct(
        private readonly Container $app,
        private readonly string $name,
        private readonly array $config,
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

        // The auth manager caches guard instances across requests (long-lived
        // workers, multiple calls in one test); a principal resolved for an
        // earlier request must never leak into this one.
        if ($this->resolvedFor !== $request) {
            $this->user = null;
            $this->credential = null;
            $this->attempted = false;
            $this->resolvedFor = $request;
        }

        if ($this->user !== null || $this->attempted) {
            return $this->user;
        }

        $this->attempted = true;

        // Full account containment (PRD 1.15, SEC-V3-04) needs no check
        // here: the resolver itself refuses an offboarded principal —
        // {@see CredentialResolver}, the containment choke point — so an
        // offboarded subject, or a credential bound to a deactivated
        // user, never resolves in the first place, indistinguishably from
        // an unknown secret.
        $credential = $this->resolveCredential($request);

        if ($credential === null) {
            return null;
        }

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

        return $this->user;
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

        $resolver = new CredentialResolver;

        return $resolver->resolve(CredentialKind::Bearer, $secret) !== null
            || $resolver->resolve(CredentialKind::Basic, $secret) !== null;
    }

    public function hasUser(): bool
    {
        return $this->user !== null;
    }

    /**
     * @return $this
     */
    public function setUser(Authenticatable $user): self
    {
        $this->user = $user;
        $this->attempted = true;
        $this->resolvedFor = $this->request();

        return $this;
    }

    /**
     * The credential that authenticated the current request, if any.
     */
    public function credential(): ?Credential
    {
        $this->user();

        return $this->credential;
    }

    private function resolveCredential(Request $request): ?Credential
    {
        $resolver = new CredentialResolver;

        /** @var list<CredentialAuthenticator> $authenticators */
        $authenticators = [
            new BearerAuthenticator($resolver),
            new BasicAuthenticator($resolver),
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

        return $this->auth()->guard($guard)->user();
    }

    private function resolveBoundUser(Credential $credential): ?Authenticatable
    {
        $provider = $this->userProvider();

        if ($provider === null) {
            return null;
        }

        return $provider->retrieveById($credential->user_id);
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
