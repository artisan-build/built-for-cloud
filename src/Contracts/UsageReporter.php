<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Contracts;

interface UsageReporter
{
    /**
     * @return array<string, array<string, mixed>>
     */
    public function perToken(): array;
}
