<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

/**
 * A deliberately leaky middleware: it logs the incoming Authorization
 * header verbatim — exactly the accidental egress D7 forbids, and (for a
 * basic credential) one that only base64-aware detection can catch. Used
 * solely to prove the harness would fire on the guard path.
 */
final class LogsAuthorizationHeaderMiddleware
{
    public function handle(Request $request, Closure $next): Response
    {
        Log::info('incoming request', ['authorization' => (string) $request->header('Authorization')]);

        return $next($request);
    }
}
