<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Middleware;

use ArtisanBuild\BuiltForCloud\Console\ActingPrincipalResolver;
use ArtisanBuild\BuiltForCloud\Console\ConsoleGuard;
use ArtisanBuild\BuiltForCloud\Console\ConsoleReentryReason;
use ArtisanBuild\BuiltForCloud\Console\ConsoleReturnTo;
use Closure;
use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * `bfc.console` — the re-entry answer for a delegated console route.
 *
 * IT IS NOT THE AUTHENTICATOR AND IT IS NOT THE CLOCK. Making the
 * console guard the guard of the route is `auth:bfc-console`'s job
 * ({@see Authenticate}), and enforcing D7's absolute cap is
 * {@see ConsoleGuard}'s, inside its own `actor()`, so the cap holds on
 * every route including ones that mount neither. This class does exactly
 * one thing the framework does not: it turns "no live delegated session"
 * into the STRUCTURED re-entry 401 the chrome's interceptor can branch
 * on, instead of the generic `AuthenticationException` Laravel would
 * raise.
 *
 * ORDER MATTERS, and it is documented rather than enforced because the
 * package mounts no console routes yet (they are PR4's and PR5's): this
 * middleware goes IN FRONT of `auth:bfc-console`, so a refused or absent
 * session gets the structured answer before the framework's own 401 can
 * fire. Behind it, `auth:bfc-console` is what makes `$request->user()`,
 * `Auth::user()` and the resolver return the delegated actor.
 *
 * IT READS THE ONE RESOLVED VALUE. Like every other package gate it asks
 * {@see ActingPrincipalResolver} rather than a guard directly, so the
 * response it writes and the principal the rest of the request acts as
 * are the same decision — and so the cases it could not see for itself
 * (the Console disabled, the reserved guard replaced by the app) arrive
 * as ordinary refusals rather than as exceptions. It gates on the LIVE
 * DELEGATED SESSION rather than on the acting principal, because it runs
 * before `auth:bfc-console` has had the chance to make that actor the
 * acting one.
 *
 * WHAT INVALIDATION MEANS: the guard flushes the WHOLE session and
 * regenerates its id, so a co-resident LOCAL (`web`) session in the same
 * browser session ends too. That is deliberate rather than incidental —
 * D14 already says the delegated principal governs a request carrying
 * both, so the request that just failed closed is a delegated request,
 * and leaving half of its session alive would leave the narrower
 * guarantee to whoever wired the routes.
 *
 * THE REFUSAL IS UNIFORM ACROSS TRANSPORTS. Every refused request gets
 * the same 401 body and the same `BFC-Console-Reentry: 1` header,
 * whether it is a Livewire XHR or a full page load. D7's full-page half
 * — redirect out through the issuer and back — needs the enter endpoint
 * (PR4) and D13's signed return state, neither of which exists yet, and
 * inventing a redirect target here would be inventing the open-redirect
 * boundary those are meant to hold. The header is the branch point the
 * chrome's interceptor (PR5) reads, so a client never has to parse a
 * body to know what happened.
 */
final class EnsureConsoleSession
{
    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $acting = app(ActingPrincipalResolver::class)->resolve();

        if ($acting->delegatedActor !== null) {
            return $next($request);
        }

        // Everything else is a refusal, and the reason comes from the
        // SAME resolution — including the cases this middleware cannot
        // see for itself: the Console disabled, the reserved guard
        // replaced by the app, or no delegated session at all.
        return $this->refuse($request, $acting->refusal ?? ConsoleReentryReason::NotAuthenticated);
    }

    /**
     * The structured re-entry 401 (Console PRD D7, as amended).
     *
     * `reentry_url` is OMITTED when the app has not configured one,
     * rather than defaulted, guessed, or emitted empty: an app that
     * cannot reach its issuer degrades honestly — the operator is
     * logged out and told why — instead of being pointed at a URL
     * nobody chose. A configured value that is not an absolute http(s)
     * URL is treated the same way, because a half-formed redirect
     * target is worse than none.
     */
    private function refuse(Request $request, ConsoleReentryReason $reason): JsonResponse
    {
        $payload = [
            'version' => 1,
            'error' => 'console_reentry_required',
            'reason' => $reason->value,
        ];

        $reentryUrl = $this->reentryUrl();

        if ($reentryUrl !== null) {
            $payload['reentry_url'] = $reentryUrl;
        }

        // A capped request is often a Livewire/XHR POST to a transport
        // endpoint, whose own URI is not the page the operator is
        // looking at — so the client may name where it wants to come
        // back to. Every candidate goes through the same relative-path
        // check, in every decoded form, and an absolute, encoded or
        // scheme-bearing one is dropped, never echoed; the request's own
        // URI is the server-chosen second choice, and `/` the third.
        $payload['return_to'] = ConsoleReturnTo::firstRelative([
            $request->input('return_to'),
            $request->getRequestUri(),
        ]);

        return new JsonResponse($payload, 401, ['BFC-Console-Reentry' => '1']);
    }

    private function reentryUrl(): ?string
    {
        $configured = config('built-for-cloud.console.reentry_url');

        if (! is_string($configured) || $configured === '') {
            return null;
        }

        $parts = parse_url($configured);

        if ($parts === false
            || ! in_array($parts['scheme'] ?? null, ['http', 'https'], true)
            || ($parts['host'] ?? '') === '') {
            return null;
        }

        return $configured;
    }
}
