<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

final class RestoreBearerRequestClassification
{
    public function handle(Request $request, Closure $next): mixed
    {
        $purpose = $request->headers->all('Purpose');

        try {
            return $next($request);
        } finally {
            if ($purpose === []) {
                $request->headers->remove('Purpose');
            } else {
                $request->headers->set('Purpose', $purpose);
            }
        }
    }
}
