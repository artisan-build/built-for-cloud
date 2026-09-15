<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Support;

final class McpRouteCacheProbe
{
    /** @return array{ok: true} */
    public function __invoke(): array
    {
        return ['ok' => true];
    }
}
