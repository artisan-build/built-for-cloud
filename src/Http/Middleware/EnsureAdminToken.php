<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Middleware;

use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\TokenRegistry;
use Closure;
use Illuminate\Http\Request;
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
            $this->tokens->observeUnauthenticatedClientIdentity($request);

            abort(401);
        }

        $token = $this->tokens->resolveModel($bearer);

        if ($token !== null) {
            // Attribution is about WHICH token authenticated, not what it is allowed to do:
            // a valid token that then 403s on scope still authenticated.
            $this->tokens->recordClientIdentityFromRequest($request, $token);

            if ($token->hasScope(Scope::Admin)) {
                return $next($request);
            }

            abort(403);
        }

        // The fallback token authenticates without a row: it is not a NoCredential event, and
        // neither is the 403 above -- that caller HAS a working credential.
        if ($this->tokens->resolve($bearer) !== null) {
            abort(403);
        }

        $this->tokens->observeUnauthenticatedClientIdentity($request);

        abort(401);
    }
}
