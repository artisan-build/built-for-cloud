<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

use ArtisanBuild\BuiltForCloud\Exceptions\AssertionRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\DelegatedActorDeactivated;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureConsoleSession;
use Carbon\CarbonImmutable;
use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Auth\SessionGuard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Facades\DB;
use SensitiveParameter;
use Symfony\Component\HttpFoundation\Request;
use Throwable;

/**
 * The `bfc-console` guard: a REAL custom guard for a delegated session,
 * with D7's ABSOLUTE assertion-age cap enforced HERE rather than by
 * whoever remembered to mount a middleware.
 *
 * IT IS A `Guard`, NOT A `StatefulGuard`, AND THAT IS THE POINT. The
 * credential-shaped methods {@see StatefulGuard} would add — `attempt`,
 * `once`, `loginUsingId`, `onceUsingId`, `viaRemember` — do not exist on
 * this class at all. There is nothing to refuse and nothing to disable,
 * because there is nothing to call.
 *
 * {@see validate()} is the one credential-shaped method the {@see Guard}
 * contract does demand, and `false` is the literal truth for every
 * input: {@see DelegatedActorProvider} has nothing to validate against.
 *
 * THERE IS EXACTLY ONE OPERATION THAT CREATES A DELEGATED PRINCIPAL, and
 * it takes the SIGNED TOKEN. {@see redeem()} accepts assertion BYTES and
 * verifies them itself, inside the same call that writes the session; no
 * public method takes an already-built {@see Assertion}, and none logs a
 * {@see DelegatedActor} in on request. That is the difference between
 * this revision and the last one: `login(DelegatedActor)` used to be
 * public, and {@see Assertion::fromVerifiedClaims()} is public and
 * documented as NOT being proof of provenance — so consuming code could
 * assemble an assertion carrying `role=admin` and hand it over, and a
 * delegated admin session existed with no signature ever checked.
 * Console PRD §4.3's "no password, no login path" now holds by
 * construction on both halves: no guard would accept credentials for
 * this principal type, and no reachable seam mints a session without a
 * verified signature.
 *
 * THE ONE PUBLIC SEAM LEFT IS {@see setUser()}, which the {@see Guard}
 * contract requires and which Laravel's own `actingAs()` uses. It is
 * bounded rather than trusted: it sets an in-memory principal for the
 * current request and writes NOTHING to the session, so a principal set
 * that way still has to survive {@see actor()} — which independently
 * demands session-bound claims and a clock inside the cap. It cannot
 * mint a delegated session, and a test pins that.
 *
 * THE ROUTE'S GUARD IS THE CONSOLE GUARD. Scoping is Laravel's own —
 * `auth:bfc-console` ({@see Authenticate}) makes this guard the one the
 * request resolves through, for that request. This package therefore
 * never calls `AuthManager::shouldUse()` and never registers a
 * `terminating` restore.
 *
 * IT IS NOT TRUE THAT NOTHING GLOBAL IS MUTATED, and that claim is not
 * made. `auth:bfc-console` calls `AuthManager::shouldUse()`, which calls
 * `setDefaultDriver()`, which writes `config('auth.defaults.guard')` —
 * exactly as `auth:web` and `auth:api` do in every Laravel application.
 * The write is real and it is process-global for the life of the config
 * repository. What makes it safe is the RUNTIME, not this class:
 * PHP-FPM starts a fresh process per request, and Octane replaces the
 * config repository with a per-request clone
 * (`Laravel\Octane\Listeners\CreateConfigurationSandbox`, on every
 * `RequestReceived`), so the write lands on a clone the next request
 * never sees. Note that Octane's `FlushAuthenticationState` does NOT
 * close it — it forgets guards and the `auth.driver` instance and never
 * touches config — so the guarantee must not be re-derived from that
 * listener.
 *
 * THE ASSUMPTION THIS DEPENDS ON: any runtime that reuses a container
 * across requests WITHOUT sandboxing config leaves the default guard
 * pointed here for every later request in that process, and a route that
 * never mentioned the Console would resolve its principal through this
 * guard. That is a property of the host runtime and cannot be detected
 * from inside a guard. Both halves — that the leak is real without a
 * sandbox, and that the clone is what closes it — are asserted in
 * `tests/ConsoleGuardScopingTest.php`.
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
 * this class never calls; `$viaRemember` only when a recaller cookie
 * actually resolves a principal, which this guard's provider never lets
 * happen (see below); `$loggedOut` only by the inner guard's own
 * `logout()`/`logoutCurrentDevice()`, and NOTHING in this class calls
 * either — {@see logout()} deliberately reimplements the storage half
 * instead, because that flag is sticky, `forgetUser()` does not clear
 * it, and a guard cached across requests would stay dead for every
 * later one; and `$recaller`/`$recallAttempted` cache a cookie that this
 * guard's provider can never turn into a principal.
 *
 * ABOUT THAT RECALLER COOKIE, precisely. `SessionGuard::user()` checks
 * for one whenever the session carries no identifier, so the remember-me
 * branch IS reachable here — a syntactically valid, correctly encrypted
 * `remember_bfc-console_*` cookie (one left by an earlier deployment
 * that used this guard name with a stock provider, say) will be decrypted
 * and looked up. It is FAIL-CLOSED rather than absent:
 * {@see DelegatedActorProvider::retrieveByToken()} returns null for every
 * input, so no principal is ever produced, `$viaRemember` never becomes
 * true, and nothing is written back. This guard never QUEUES a recaller
 * cookie — {@see redeem()} logs in with remembering off, and there is no
 * other login path — so the only such cookie that can exist is one this
 * package did not write. `tests/ConsoleRememberMeTest.php` drives the
 * whole of that through a real request, and observes that the branch was
 * entered rather than assuming it.
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
        private readonly AssertionVerifier $verifier,
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
     * THE ONE OPERATION THAT CREATES A DELEGATED PRINCIPAL: verify signed
     * assertion bytes and, only if they hold, turn them into a live
     * delegated session. This is the API PR4's `/bfc/console/enter`
     * endpoint calls, and the reason PR4 cannot get the ordering wrong.
     *
     * It takes the TOKEN, not an {@see Assertion}, and that is the whole
     * point: {@see Assertion::fromVerifiedClaims()} is public and is
     * documented as not being proof of provenance, so an operation that
     * accepted an assertion object would accept a forged one. Here the
     * signature, the issuer, the audience, the TTL bound and the clocks
     * are all checked by {@see AssertionVerifier} inside this call, and
     * there is no other public seam that logs a delegated actor in.
     *
     * Five things happen, in this order, and each is a security property
     * that fails quietly if it moves:
     *
     *  1. **Verification**, first, and it throws
     *     {@see AssertionRefused} before anything is read or written.
     *  2. **The handoff is recorded** on the shadow actor row, refreshing
     *     its `last_handoff_*` copy — including for an actor about to be
     *     refused, so an operator can see that a contained human
     *     attempted entry and with what claims. It is committed on its
     *     own, BEFORE the decision, precisely so a refusal cannot roll
     *     the record back.
     *  3. **The actor is re-read UNDER A ROW LOCK, and a deactivated one
     *     is refused BEFORE anything is logged in.** Two races close
     *     here. The provider only refuses on the NEXT rehydration, so an
     *     endpoint that logged in first would give a contained principal
     *     the whole redemption request — long enough to act. And checking
     *     `deactivated_at` on the model written a moment earlier is a
     *     read that has already gone stale.
     *     {@see DelegatedActor::deactivate()} takes the same lock, so the
     *     two strictly order.
     *  4. **The claims are bound to the SESSION**, not read later off the
     *     shared row. PRD D8 makes them per-mint; {@see DelegatedClaims}
     *     carries the escalation this prevents.
     *  5. **The login happens last and INSIDE the transaction that still
     *     holds the lock.** An earlier revision closed the transaction on
     *     the locked read and began the session outside it, which reopens
     *     the race it had just closed: a deactivation committing in that
     *     window leaves a live delegated session behind a row that says
     *     contained.
     *
     * The session is never remembered. There is no `$remember` anywhere
     * on this class: a delegated session's life is bounded by D7's clocks
     * and by nothing else, and a cookie that outlived them would be the
     * one way the browser got a say in revocation.
     *
     * KNOWN LIMIT, stated: `lockForUpdate()` compiles to nothing on
     * SQLite, so this package's own suite cannot prove the ORDERING —
     * only that the re-read happens inside the transaction and that a row
     * deactivated before it is refused. A mutation-debt row records it.
     *
     * @throws AssertionRefused when the token does not verify
     * @throws DelegatedActorDeactivated when this deployment has contained the actor
     */
    public function redeem(#[SensitiveParameter] string $assertionToken): DelegatedActor
    {
        $assertion = $this->verifier->verify($assertionToken);

        $recorded = DelegatedActor::recordHandoff($assertion);

        // Whether this redemption has begun mutating the session. It is
        // set immediately BEFORE the first write, so the compensation
        // below runs for everything that can fail from that point on and
        // for nothing that fails before it — a refusal at the locked read
        // has damaged nothing, and must not flush a co-resident local
        // session as a side effect.
        $begun = false;

        try {
            /** @var DelegatedActor */
            return DB::transaction(function () use ($assertion, $recorded, &$begun): DelegatedActor {
                $locked = DelegatedActor::lockedById($recorded->getKey());

                if ($locked === null || ! $locked->isActive()) {
                    throw DelegatedActorDeactivated::cannotEnter();
                }

                $begun = true;

                ConsoleSession::begin($this->session, $assertion);

                $this->forget();
                $this->inner->login($locked, false);

                return $locked;
            });
        } catch (Throwable $failure) {
            // COMPENSATION, and it is load-bearing rather than tidy.
            // `SessionGuard::login()` writes the identifier and
            // REGENERATES the session before it dispatches the `Login`
            // event, so a customer-defined listener that throws — an
            // audit backend that is down, say — leaves a session already
            // carrying the delegated identifier AND this session's
            // claims. The database transaction rolls back; the session
            // does not. And a throw does not simply abandon the request:
            // Laravel's routing pipeline renders it into a response, so
            // `StartSession` still saves that session and hands the
            // browser its cookie. Without this, the NEXT request would
            // rehydrate an authenticated delegated admin from a
            // redemption that reported failure.
            //
            // It runs AFTER the transaction has rolled back rather than
            // inside it, so that invalidating the session — which on the
            // `database` session driver is itself a write — is not
            // undone by the rollback, and so that a failure at COMMIT is
            // compensated too.
            if ($begun) {
                $this->destroySession();
            }

            throw $failure;
        }
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
     * Set the in-memory principal for THIS request only. Required by the
     * {@see Guard} contract, and what Laravel's own `actingAs()` calls.
     *
     * It is a bounded seam, not a way in. It writes NOTHING to the
     * session — no identifier, no claims, no issued-at marker — so a
     * principal set here still has to survive {@see actor()}, which
     * independently requires session-bound claims and an assertion age
     * inside the cap. A caller that sets a delegated actor and nothing
     * else gets a refusal, not a session, and the next request has
     * nothing to rehydrate.
     *
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
     * enter/leave endpoints (PR4, PR5) rather than for anything in this
     * release.
     *
     * IT DOES NOT CALL THE INNER GUARD'S `logout()`, and that is the
     * whole of the method. `SessionGuard::logout()` sets a STICKY
     * `loggedOut` flag, `SessionGuard::user()` returns null immediately
     * whenever it is set, `forgetUser()` does not clear it, and the auth
     * manager caches guard instances for the life of the process. So a
     * leave on one request would make this guard permanently dead for
     * every later request in a long-lived worker — a different, perfectly
     * valid delegated session on request B rejected because of what
     * request A did. That is the same class of cross-request state leak
     * the per-request reset above exists to prevent, so leaving is done
     * the way refusal is done: forget the principal and destroy the
     * session, and never set the flag.
     *
     * Nothing this package writes is lost by skipping the framework's
     * version. The only thing `SessionGuard::logout()` does beyond this
     * is clear a RECALLER cookie, and this guard never queues one; a
     * stale recaller left by something else cannot authenticate anybody
     * here (see the class docblock) and is not this method's to forget.
     */
    public function logout(): void
    {
        $this->destroySession();
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
        $this->destroySession();

        $this->refusal = $reason;
    }

    /**
     * Forget the principal and destroy the session — the one storage
     * effect refusal, leaving and redemption's compensation all share.
     *
     * `$session->invalidate()` flushes the whole session and regenerates
     * its id, which is everything `SessionGuard::logout()` would have
     * done to storage. What it deliberately does NOT do is set the inner
     * guard's sticky `loggedOut` flag; {@see logout()} says why that
     * matters, and it matters identically here.
     */
    private function destroySession(): void
    {
        $this->forget();

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
