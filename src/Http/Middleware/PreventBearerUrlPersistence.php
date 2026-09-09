<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

final class PreventBearerUrlPersistence
{
    /** @var list<string> */
    private const ROUTES = ['bfc.password.reset', 'bfc.invitations.accept'];

    /** @param Closure(Request): Response $next */
    public function handle(Request $request, Closure $next): mixed
    {
        if (! in_array($request->route()?->getName(), self::ROUTES, true)) {
            return $next($request);
        }

        $response = $next($request);
        $request->session()->forget(['_previous.url', '_previous.route']);
        $request->headers->set('Purpose', 'prefetch');

        return $response;
    }
}
