<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Middleware;

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
            abort(401);
        }

        $token = $this->tokens->resolveModel($bearer);

        if ($token !== null) {
            if ($token->hasAbility('admin')) {
                return $next($request);
            }

            abort(403);
        }

        if ($this->tokens->resolve($bearer) !== null) {
            abort(403);
        }

        abort(401);
    }
}
