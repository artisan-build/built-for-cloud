<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\ApiToken;

final class SecondStoreResolver
{
    public function resolve(string $secret): ?ApiToken
    {
        return ApiToken::query()->where('token_hash', hash('sha256', $secret))->first();
    }
}
