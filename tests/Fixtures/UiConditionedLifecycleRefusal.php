<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Credential;
use RuntimeException;

final class UiConditionedLifecycleRefusal
{
    public function assertUsable(Credential $credential): void
    {
        if (config('built-for-cloud.ui.session_management') === true && $credential->revoked_at !== null) {
            throw new RuntimeException('The credential is revoked.');
        }
    }
}
