<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Contracts\CredentialAuthenticator;
use ArtisanBuild\BuiltForCloud\Credential;
use Illuminate\Http\Request;

final class SecondStoreAuthenticator implements CredentialAuthenticator
{
    public function __construct(private SecondStoreResolver $resolver) {}

    public function credential(Request $request): ?Credential
    {
        $secret = $request->bearerToken();

        $this->resolver->resolve($secret ?? '');

        return null;
    }
}
