<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Session\Middleware\StartSession;
use Symfony\Component\HttpFoundation\Response;

final class PreventBearerUrlPersistence
{
    /** @var list<string> */
    private const ROUTES = ['bfc.password.reset', 'bfc.invitations.accept'];

    public function __construct(private readonly StartSession $middleware) {}

    /** @param Closure(Request): Response $next */
    public function handle(Request $request, Closure $next): mixed
    {
        if (! in_array($request->route()?->getName(), self::ROUTES, true)) {
            return $this->middleware->handle($request, $next);
        }

        $purpose = $request->headers->all('Purpose');

        try {
            return $this->middleware->handle($request, static function (Request $request) use ($next): Response {
                $response = $next($request);
                $request->session()->forget(['_previous.url', '_previous.route']);
                $request->headers->set('Purpose', 'prefetch');

                return $response;
            });
        } finally {
            if ($purpose === []) {
                $request->headers->remove('Purpose');
            } else {
                $request->headers->set('Purpose', $purpose);
            }
        }
    }

    public function terminate(Request $request, Response $response): void
    {
        if (method_exists($this->middleware, 'terminate')) {
            $this->middleware->terminate($request, $response);
        }
    }
}
