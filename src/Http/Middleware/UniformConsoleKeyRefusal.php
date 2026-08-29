<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Middleware;

use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;

/**
 * One refusal for every pre-authorization failure on the console key
 * surface (Console PRD D12, rework A5).
 *
 * {@see EnsureCredentialAdmin} answers `401` for a missing, unknown or
 * dead bearer and `403` for a live credential lacking the route's
 * ability. On the OPERATOR CREDENTIAL surfaces that split is right and
 * documented: a caller who reaches the `403` has already proved it holds
 * a live credential, so nothing about credential existence leaks.
 *
 * This route is the exception, and the reason is what a probe would buy
 * here rather than any general principle. A filed console key is a
 * standing authority to enter this deployment as an admin, so the
 * interesting question for someone holding a stolen or stale bearer is
 * not "does this string name a row" but "is this the credential that can
 * take the deployment" — and the `401`/`403` split answers exactly that,
 * for free, before any rate limit has meaningfully bitten. Collapsing
 * them means a prober learns only that it was refused.
 *
 * It wraps the gate rather than replacing it: authorization is still
 * {@see EnsureCredentialAdmin}'s decision and its `denied_action` audit
 * still records WHICH failure occurred, with the actor typed where one
 * is known. The distinction is kept internally and dropped externally,
 * which is the only place it was ever a leak.
 *
 * Scope, precisely: it normalizes `401` and `403` only. A `429` from the
 * throttle in front of it is untouched (a rate limit that lied about
 * being a rate limit would be unusable), and so is every status the
 * controller itself returns — the controller's `403` for a claim code
 * without key-custody authority never reaches this middleware, because
 * the controller returns a response rather than aborting.
 */
final class UniformConsoleKeyRefusal
{
    /**
     * The one status every pre-authorization failure answers with.
     * `403` rather than `401`: two of the three cases are genuinely
     * "not permitted", and a `401` invites a client to retry with
     * credentials it has already shown are not the right ones.
     */
    public const int STATUS = 403;

    /**
     * The one body. Server-authored and constant — it names no
     * credential, no ability and no reason.
     */
    public const string MESSAGE = 'This request is not permitted to write console countersigning keys.';

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        try {
            $response = $next($request);
        } catch (HttpExceptionInterface $refusal) {
            // The gate aborts rather than returning, so its refusals
            // arrive here as exceptions.
            return in_array($refusal->getStatusCode(), [401, 403], true)
                ? $this->uniform()
                : throw $refusal;
        }

        // Belt for the same braces: a gate that ever answered by
        // RETURNING a 401/403 instead of aborting would otherwise slip
        // its status past this middleware unchanged.
        return in_array($response->getStatusCode(), [401, 403], true)
            ? $this->uniform()
            : $response;
    }

    private function uniform(): JsonResponse
    {
        return response()->json(['message' => self::MESSAGE], self::STATUS);
    }
}
