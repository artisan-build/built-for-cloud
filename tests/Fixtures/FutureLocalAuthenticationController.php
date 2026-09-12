<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

final class FutureLocalAuthenticationController
{
    public function authenticate(): string
    {
        return 'inventory-control';
    }
}
