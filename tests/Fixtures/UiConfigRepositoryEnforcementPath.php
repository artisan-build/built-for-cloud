<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use RuntimeException;

final class UiConfigRepositoryEnforcementPath
{
    public function __construct(private ConfigRepository $config) {}

    public function enforce(): void
    {
        if (! $this->config->get('built-for-cloud.ui.rogue_repository_gate')) {
            throw new RuntimeException('The repository-backed UI gate denied access.');
        }
    }
}
