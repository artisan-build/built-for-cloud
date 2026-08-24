<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Middleware;

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\ClientIdentity;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\TokenRegistry;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

final class EnsureAdminToken
{
    public function __construct(private readonly TokenRegistry $tokens) {}

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $bearer = $request->bearerToken();

        if ($bearer === null || $bearer === '') {
            abort(401);
        }

        $token = $this->tokens->resolveModel($bearer);

        if ($token !== null) {
            // Attribution is about WHICH token authenticated, not what it is allowed to do:
            // a valid token that then 403s on scope still authenticated.
            $this->recordClientIdentity($request, $token);

            if ($token->hasScope(Scope::Admin)) {
                return $next($request);
            }

            abort(403);
        }

        if ($this->tokens->resolve($bearer) !== null) {
            abort(403);
        }

        abort(401);
    }

    /**
     * Record the client identity when the request carries a contract-conforming one.
     *
     * A malformed header is logged and dropped: it must never break the customer's request,
     * and it must never influence authentication or authorisation. An absent header leaves
     * any previously stored identity untouched.
     */
    private function recordClientIdentity(Request $request, ApiToken $token): void
    {
        $values = $request->headers->all(ClientIdentity::HEADER);

        if ($values === []) {
            return;
        }

        $identity = ClientIdentity::fromRequest($request);

        if ($identity !== null) {
            $this->tokens->recordClientIdentity($token, $identity);

            return;
        }

        $only = count($values) === 1 ? $values[array_key_first($values)] : null;

        // Never log the value itself: it is attacker-controlled and unvalidated.
        Log::warning('Built for Cloud discarded a malformed client identity header.', [
            'header' => ClientIdentity::HEADER,
            'values' => count($values),
            'bytes' => is_string($only) ? strlen($only) : null,
            'reason' => is_string($only)
                ? ClientIdentity::rejectionReason($only)
                : 'not exactly one header value',
        ]);
    }
}
