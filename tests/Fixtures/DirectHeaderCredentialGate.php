<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Credential;
use Closure;
use Illuminate\Http\Request;

final class DirectHeaderCredentialGate
{
    public function handle(Request $request, Closure $next): mixed
    {
        $secret = (string) $request->header('Authorization');
        $credential = Credential::query()->where('secret_hash', hash('sha256', $secret))->first();

        return $credential instanceof Credential ? $next($request) : response('Unauthorized', 401);
    }
}
