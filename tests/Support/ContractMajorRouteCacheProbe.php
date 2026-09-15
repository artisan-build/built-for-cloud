<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Support;

final class ContractMajorRouteCacheProbe
{
    public static int $runs = 0;

    /** @return array{ok: true} */
    public function __invoke(): array
    {
        self::$runs++;

        return ['ok' => true];
    }
}
