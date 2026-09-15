<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

final class FutureLocalAuthenticationController
{
    public function authenticate(): string
    {
        return 'inventory-control';
    }
}
