<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Contracts;

use ArtisanBuild\BuiltForCloud\BoundCredentialScope;
use Illuminate\Http\Request;

interface ResolvesAsymmetricEnrollmentScope
{
    public function resolve(Request $request, string $application): ?BoundCredentialScope;
}
