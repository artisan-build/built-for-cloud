<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\CredentialAuthorizationFlow;
use Illuminate\Support\Facades\DB;

final class RogueDeviceCredentialExchange
{
    public function exchange(): void
    {
        $flow = CredentialAuthorizationFlow::Device;
        DB::table('credentials')->insert(['name' => $flow->value]);
    }
}
