<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Contracts;

use ArtisanBuild\BuiltForCloud\Credential;
use Illuminate\Http\Request;

/**
 * A per-kind authentication strategy: extract this kind's secret from the
 * request and resolve it to an active credential row, or nothing. Resolution
 * must not stamp usage — the guard stamps only when the request fully
 * authenticates.
 */
interface CredentialAuthenticator
{
    public function credential(Request $request): ?Credential;
}
