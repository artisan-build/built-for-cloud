<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Support;

use ParagonIE\Paseto\Keys\Version4\AsymmetricSecretKey;

final class P6LiveSecretMaterial
{
    public static function signingKey(AsymmetricSecretKey $key): string
    {
        return bin2hex($key->raw());
    }
}
