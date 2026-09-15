<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\CredentialAuthorizationFlow;
use Illuminate\Support\Facades\DB;

final class RogueLoopbackCredentialSelector
{
    public function select(string $secret): mixed
    {
        $flow = CredentialAuthorizationFlow::Loopback;

        return DB::table('credentials')
            ->where('secret_hash', hash('sha256', $flow->value.$secret))
            ->first();
    }
}
