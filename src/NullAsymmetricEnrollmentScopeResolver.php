<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Contracts\ResolvesAsymmetricEnrollmentScope;
use Illuminate\Http\Request;

final class NullAsymmetricEnrollmentScopeResolver implements ResolvesAsymmetricEnrollmentScope
{
    public function resolve(Request $request, string $application): ?BoundCredentialScope
    {
        return null;
    }
}
