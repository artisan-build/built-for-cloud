<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Contracts\UsageReporter;

final class NullUsageReporter implements UsageReporter
{
    /**
     * @return array<string, array<string, mixed>>
     */
    public function perToken(): array
    {
        return [];
    }
}
