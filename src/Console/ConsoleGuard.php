<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

use ArtisanBuild\BuiltForCloud\Exceptions\DelegatedActorDeactivated;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureConsoleSession;
use Carbon\CarbonImmutable;
use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Auth\SessionGuard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Session\Session;
use Symfony\Component\HttpFoundation\Request;

/**
 * The `bfc-console` guard: a REAL custom guard for a delegated session,
 * with D7's ABSOLUTE assertion-age cap enforced HERE rather than by
 * whoever remembered to mount a middleware.
 *
 * IT IS A `Guard`, NOT A `StatefulGuard`, AND THAT IS THE POINT. The six
 * credential-shaped methods {@see StatefulGuard} would add — `attempt`,
 * `once`, `loginUsingId`, `onceUsingId`, `viaRemember`, `logout` with a
 * recaller — do not exist on this class at all. There is nothing to
 * refuse and nothing to disable, because there is nothing to call: the
 * only way a delegated principal comes into being is
 * {@see login()}, which only {@see ConsoleHandoff::redeem()} calls, after
 * {@see AssertionVerifier} has accepted a signed assertion. Console PRD
 * §4.3's "no password, no login path" is therefore STRUCTURAL — no guard
 * exists that would accept credentials for this principal type — rather
 * than a set of methods that throw.
 *
 * {@see validate()} is the one credential-shaped method the {@see Guard}
 * contract does demand, and `false` is the literal truth for every
 * input: {@see DelegatedActorProvider} has nothing to validate against.
 *
 * THE ROUTE'S GUARD IS THE CONSOLE GUARD. Scoping is Laravel's own —
 * `auth:bfc-console` ({@see Authenticate}) makes this guard the one the
 * request resolves through, for that request. This package therefore
 * never calls `AuthManager::shouldUse()`, never registers a `terminating`
 * restore, and mutates no process-global auth state of its own.
 *
 * WHY THE CAP LIVES IN THE GUARD AND NOT IN A MIDDLEWARE. A cap applied
 * only in middleware is a cap a route can omit: `auth('bfc-console')
 * ->user()` on any other route would keep returning the stale actor, and
 * Laravel's sliding idle window would keep renewing the session for as
 * long as the operator stayed active — indefinitely, rather than 120
 * minutes. So the cap lives in {@see actor()}: every reader of this
 * guard, on every route, gets the same answer, and the session is
 * destroyed the first time any of them asks.
 *
 * COMPOSITION, NOT INHERITANCE. The inner guard is a real
 * {@see SessionGuard} built by the framework's own
 * `AuthManager::createSessionDriver()`, and this class delegates to it.
 * Subclassing would mean mirroring that factory's constructor — which
 * has gained parameters within a single major (`rehashOnLogin`,
 * `timeboxDuration`, `hashKey`) — and re-mirroring it on every upgrade.
 *
 * WHAT COUNTS AS A REFUSAL, and all of them destroy the session:
 *
 *  - the assertion is older than the absolute cap ({@see ConsoleSessionClock});
 *  - the session's issued-at marker is missing, unparseable, or dated
 *    past the configured clock skew into the future — fail closed, an
 *    age that cannot be established is not an age inside the cap;
 *  - the session's CLAIMS (display name, role, agency) are missing or
 *    malformed: a delegated session whose role cannot be read has no
 *    role, and is not waved through with a default one;
 *  - the principal is not an active {@see DelegatedActor};
 *  - console session STATE survives with no principal behind it — an
 *    orphan left by a deactivated actor or a half-cleared session.
 *
 * THE CLOCK IS EVALUATED FIRST, before the inner guard is asked, so a
 * capped session reports `assertion_age_cap` rather than the
 * `session_invalidated` a vanished principal would produce.
 *
 * REFUSAL DOES NOT CALL `logout()`. It forgets the in-memory principal
 * and INVALIDATES the session (flushed, id regenerated), which does
 * everything `logout()` would have done to storage — but `logout()`
 * would also set the inner guard's sticky `loggedOut` flag, and the auth
 * manager caches guard instances for the life of the process. On a
 * long-lived worker that flag would make this guard permanently dead for
 * every later request, which is the same class of bug as the stale
 * principal below. Refusal is confined to the request that earned it by
 * {@see $refusal}, which short-circuits before the inner guard is
 * consulted again.
 *
 * PER-REQUEST STATE, exhaustively. The auth manager caches guards across
 * requests, and resetting only this wrapper is not enough: the inner
 * {@see SessionGuard} caches its own `$user`, and `setRequest()` does
 * not clear it — so a principal resolved in request A would be returned
 * in request B. {@see forgetIfNewRequest()} therefore calls the
 * framework's own `forgetUser()` on the inner guard as well. The inner's
 * remaining mutable state is accounted for rather than hoped about:
 * `$lastAttempted` is only written by `attempt`/`once`/`basic`, which
 * this class never calls; `$viaRemember` only by a recaller or a
 * remembered login, and this guard's provider answers null to
 * `retrieveByToken` and never remembers; `$loggedOut` only by `logout()`,
 * which refusal no longer calls; and `$recaller`/`$recallAttempted`
 * cache a cookie that this guard's provider can never turn into a
 * principal.
 *
 * The guard does not answer the request; it only decides. The refusal
 * REASON is what {@see EnsureConsoleSession} turns into the structured
 * 401.
 */
final class ConsoleGuard implements Guard
{
    private ?ConsoleReentryReason $refusal = null;

    private ?DelegatedActor $resolved = null;

    private ?DelegatedClaims $claims = null;

    private ?Request $decidedFor = null;

    public function __construct(
        private readonly SessionGuard $inner,
        private readonly Session $session,
    ) {}

    /**
     * The delegated actor acting on this request, or null.
     *
     * This is the enforcement point, and it has a SIDE EFFECT by design:
     * a refused session is destroyed here, on the first read, whatever
     * route asked.
     */
    public function user(): ?Authenticatable
    {
        return $this->actor();
    }

    /**
     * The same answer as {@see user()}, typed as what this guard
     * actually resolves. Callers that need the delegated principal —
     * {@see ActingPrincipalResolver} above all — use this one.
     */
    public function actor(): ?DelegatedActor
    {
        $this->forgetIfNewRequest();

        if ($this->refusal instanceof ConsoleReentryReason) {
            return null;
        }

        if ($this->resolved instanceof DelegatedActor) {
            return $this->resolved;
        }

        $hasState = ConsoleSession::hasState($this->session);

        // The clock goes first so that a capped session reports the cap
        // rather than the session_invalidated a missing principal would
        // produce.
        if ($hasState) {
            $reason = ConsoleSessionClock::evaluate($this->session, CarbonImmutable::now());

            if ($reason instanceof ConsoleReentryReason) {
                $this->refuse($reason);

                return null;
            }
        }

        $principal = $this->inner->user();

        if ($principal === null) {
            // Console state with no principal behind it is an orphan:
            // the actor was deactivated, or the login half is gone. It
            // does not outlive its principal.
            if ($hasState) {
                $this->refuse(ConsoleReentryReason::SessionInvalidated);
            }

            return null;
        }

        $user = self::asDelegatedActor($principal);
        $claims = ConsoleSession::claims($this->session);

        if ($user === null || ! $user->isActive() || ! $claims instanceof DelegatedClaims) {
            // Either the session carries a principal this guard's own
            // provider could not have produced (a swapped provider, a
            // hand-built session), or the actor is contained, or the
            // session's claims cannot be read. All three are refusals:
            // a delegated session whose role cannot be established has
            // no role, and is never waved through with a default one.
            $this->refuse(ConsoleReentryReason::SessionInvalidated);

            return null;
        }

        $this->claims = $claims;
        $this->resolved = $user;

        return $user;
    }

    /**
     * The principal as a delegated actor, or null when it is not one.
     *
     * A one-line helper rather than an inline `instanceof` on purpose:
     * static analysis narrows a guard's `user()` to the application's
     * CONFIGURED auth model, which makes an inline check look
     * impossible and would quietly delete the very branch that keeps a
     * foreign principal out of this guard.
     */
    private static function asDelegatedActor(Authenticatable $principal): ?DelegatedActor
    {
        return $principal instanceof DelegatedActor ? $principal : null;
    }

    /**
     * The SESSION-BOUND claims this request acts under (D8), or null when
     * no delegated actor is acting. Resolved by {@see actor()} from the
     * session, never from the actor row — see {@see DelegatedClaims} for
     * why the row cannot hold them.
     */
    public function claims(): ?DelegatedClaims
    {
        $this->actor();

        return $this->claims;
    }

    /**
     * Why the delegated session on this request was refused, or null when
     * it was not refused (including when there never was one).
     */
    public function refusalReason(): ?ConsoleReentryReason
    {
        $this->actor();

        return $this->refusal;
    }

    /**
     * Begin a delegated session. Refuses a deactivated actor outright:
     * the provider's own refusal only bites on the NEXT rehydration, so
     * without this a contained actor would be the principal for the whole
     * redemption request.
     *
     * There is no `$remember` parameter, and that is not an omission —
     * a delegated session's life is bounded by D7's clocks and by
     * nothing else, and a cookie that outlived them would be the one way
     * the browser got a say in revocation. The inner guard is always
     * called with remembering off.
     *
     * {@see ConsoleHandoff::redeem()} is the only path that should call
     * this; it is what re-reads the actor under a row lock first, inside
     * the transaction that holds the lock.
     *
     * @throws DelegatedActorDeactivated
     */
    public function login(DelegatedActor $actor): void
    {
        if (! $actor->isActive()) {
            throw DelegatedActorDeactivated::cannotEnter();
        }

        $this->forget();
        $this->inner->login($actor, false);
    }

    public function check(): bool
    {
        return $this->actor() !== null;
    }

    public function guest(): bool
    {
        return ! $this->check();
    }

    /**
     * Always the TYPE-QUALIFIED identifier, never a bare integer — the
     * return type is narrower than the {@see Guard} contract's
     * `int|string|null` because this guard's principal has exactly one
     * identifier shape, and that shape is the whole point (see
     * {@see DelegatedActor::getAuthIdentifier()}).
     */
    public function id(): ?string
    {
        return $this->actor()?->getAuthIdentifier();
    }

    public function hasUser(): bool
    {
        return $this->actor() !== null;
    }

    /**
     * @return $this
     */
    public function setUser(Authenticatable $user): self
    {
        $this->forget();
        $this->inner->setUser($user);

        return $this;
    }

    /**
     * Always false, for every input. Not "these credentials do not
     * match" — there is nothing to match: {@see DelegatedActorProvider}
     * answers null to `retrieveByCredentials` and false to
     * `validateCredentials` unconditionally, and this guard has no
     * `attempt()` that could act on a true answer even if one existed.
     *
     * @param  array<string, mixed>  $credentials
     */
    public function validate(array $credentials = []): bool
    {
        return false;
    }

    /**
     * End the delegated session. Not part of any interface this class
     * implements — {@see Guard} has no `logout()` — and offered for the
     * enter/leave endpoints (PR4) rather than for anything in this
     * release.
     */
    public function logout(): void
    {
        $this->forget();
        $this->inner->logout();
    }

    /**
     * The session key the inner guard stores the delegated principal
     * under. Exposed for the enter endpoint (PR4) and for tests that seed
     * a session directly, so neither has to reconstruct Laravel's naming.
     */
    public function getName(): string
    {
        return $this->inner->getName();
    }

    private function refuse(ConsoleReentryReason $reason): void
    {
        $this->refusal = $reason;
        $this->resolved = null;
        $this->claims = null;

        // Forget, do not log out — see the class docblock on why the
        // sticky `loggedOut` flag must not be set here. The invalidate
        // below does everything logout() would have done to storage.
        $this->inner->forgetUser();
        $this->session->invalidate();
    }

    /**
     * The auth manager caches guard instances across requests, so a
     * decision made for an earlier request must never answer for this
     * one — and neither must the INNER guard's own cached principal,
     * which `setRequest()` does not clear.
     */
    private function forgetIfNewRequest(): void
    {
        $request = $this->inner->getRequest();

        if ($this->decidedFor !== $request) {
            $this->forget();
            $this->inner->forgetUser();
            $this->decidedFor = $request;
        }
    }

    private function forget(): void
    {
        $this->refusal = null;
        $this->resolved = null;
        $this->claims = null;
    }
}
