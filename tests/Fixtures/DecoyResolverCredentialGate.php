<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Auth\CredentialResolver;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use Closure;
use Illuminate\Http\Request;

final class DecoyResolverCredentialGate
{
    public function __construct(private readonly CredentialResolver $resolver) {}

    public function handle(Request $request, Closure $next): mixed
    {
        $secret = (string) $request->header('Authorization');
        $this->resolver->resolve(CredentialKind::Bearer, $secret);
        $credential = Credential::query()->where('secret_hash', hash('sha256', $secret))->first();

        return $credential instanceof Credential ? $next($request) : response('Unauthorized', 401);
    }
}
