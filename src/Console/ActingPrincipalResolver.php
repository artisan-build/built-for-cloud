<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

use ArtisanBuild\BuiltForCloud\Auth\CredentialGuard;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureConsoleSession;
use Illuminate\Auth\AuthManager;
use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;

/**
 * D14's single acting principal: ONE value, read by the principal, the
 * chrome and the audit stream alike.
 *
 * THIS CLASS MUTATES NOTHING — and that is a claim about this class, not
 * about the request. An earlier revision repointed the application's
 * DEFAULT GUARD (`AuthManager::shouldUse()`, undone from a container
 * `terminating` callback) so that `Auth::user()` would agree with it.
 * That was the wrong answer to a real problem: once the delegated actor
 * is the process-global default, every code path assuming default-guard
 * semantics is pointed at it, and the restore is an ordering hazard on
 * every long-lived runtime. The framework already has the mechanism —
 * `auth:bfc-console` ({@see Authenticate}) makes the console guard the
 * guard OF THE ROUTE for the request it runs in — so this class only
 * ever READS.
 *
 * That middleware DOES write `config('auth.defaults.guard')`, exactly as
 * `auth:web` does; what keeps the write from outliving the request is
 * the runtime's config sandboxing, not anything here. {@see ConsoleGuard}
 * carries the full statement and the runtime assumption it depends on,
 * and `tests/ConsoleGuardScopingTest.php` asserts both halves.
 *
 * WHAT IT READS. The route's applicable guard is
 * `AuthManager::getDefaultDriver()`: on a console route that is
 * `bfc-console`, because Laravel's own auth middleware just made it so;
 * everywhere else it is whatever the app configured. The delegated
 * session is read from {@see ConsoleGuard} directly, because that guard
 * is where D7's clocks are enforced and a request must not be able to
 * carry a live-looking delegated session past them by being routed
 * somewhere the guard was never consulted.
 *
 * PRECEDENCE — delegated wins, and there is no union. A REFUSAL wins
 * over everything, on every route: a request whose delegated session has
 * just been invalidated resolves nobody, and never falls back to a
 * co-resident local user.
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
 * cached answer. In practice every consumer that matters — the acting
 * principal and the chrome's attribution branch — runs behind the
 * route's auth middleware and therefore shares one instance, which is
 * what D14 requires. The one deliberate exception is
 * {@see EnsureConsoleSession}, which runs IN FRONT of it and asks only
 * whether a delegated session exists, a question the applicable guard
 * cannot change the answer to.
 *
 * CLAIMS COME FROM THE SESSION. The role and the attribution this
 * resolution carries are the ones THIS session's own handoff wrote
 * ({@see DelegatedClaims}), never the shadow row's `last_handoff_*`
 * copy, which a later handoff for the same subject overwrites.
 */
final class ActingPrincipalResolver
{
    private ?ActingPrincipal $resolved = null;

    private ?Request $resolvedFor = null;

    private ?string $resolvedUnder = null;

    public function __construct(private readonly Container $app) {}

    /**
     * The acting principal for the CURRENT request. Repeated calls
     * within one request return the identical instance.
     */
    public function resolve(): ActingPrincipal
    {
        $request = $this->request();
        $applicable = $this->applicableGuardName();

        if ($this->resolvedFor !== $request || $this->resolvedUnder !== $applicable) {
            $this->resolved = null;
            $this->resolvedFor = $request;
            $this->resolvedUnder = $applicable;
        }

        return $this->resolved ??= $this->resolveNow();
    }

    private function resolveNow(): ActingPrincipal
    {
        $console = $this->consoleGuard();

        // Reading the guard is what ENFORCES D7's cap, so it happens on
        // every resolution rather than only on console routes — that is
        // how a capped session dies on a route that mounts no console
        // middleware at all.
        $actor = $console?->actor();
        $claims = $console?->claims();
        $refusal = $console?->refusalReason();

        if ($refusal instanceof ConsoleReentryReason) {
            return ActingPrincipal::refused($refusal);
        }

        if ($this->applicableGuardName() === ConsoleGuardConfiguration::GUARD) {
            // The route's own guard is the console guard, so the
            // delegated actor is what everything behind it acts as.
            return $actor instanceof DelegatedActor && $claims instanceof DelegatedClaims
                ? ActingPrincipal::delegated($actor, $claims)
                : ActingPrincipal::none($actor);
        }

        $guard = $this->localGuardName();

        if ($guard === null) {
            return ActingPrincipal::none($actor);
        }

        $user = $this->auth()->guard($guard)->user();

        // A delegated actor reached through a guard that is NOT this
        // package's carries no verified session claims — nothing could
        // attribute or authorize from it — so it is not a local
        // principal either. The typed branch fails towards nobody.
        if ($user === null || $user instanceof DelegatedActor) {
            return ActingPrincipal::none($actor);
        }

        return ActingPrincipal::local($guard, $user, $actor);
    }

    /**
     * The package's own delegated guard, or null when this app has not
     * enabled the Console, has no `bfc-console` guard configured, or has
     * replaced it with one of its own. Asking the guard rather than the
     * session is what keeps the cap, the claim check and this resolution
     * reading one decision.
     */
    private function consoleGuard(): ?ConsoleGuard
    {
        if (! is_array(config('auth.guards.'.ConsoleGuardConfiguration::GUARD))) {
            return null;
        }

        $guard = $this->auth()->guard(ConsoleGuardConfiguration::GUARD);

        return $guard instanceof ConsoleGuard ? $guard : null;
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
     * A headless app ships `auth.defaults.guard => null` and
     * `auth.guards => []`, and asking the AuthManager for a guard that
     * does not exist throws — so structural absence is read as "nobody
     * is acting locally", the same stance {@see CredentialGuard} takes.
     * A CONFIGURED guard that throws during resolution is a different
     * state and is left to propagate.
     */
    private function localGuardName(): ?string
    {
        $guard = $this->applicableGuardName();

        if ($guard === null || $guard === ConsoleGuardConfiguration::GUARD) {
            return null;
        }

        return is_array(config('auth.guards.'.$guard)) ? $guard : null;
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
