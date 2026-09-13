<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

/**
 * Counts its own restoration. Nested inside a queued-listener wrapper, it proves
 * whether reading the wrapper's class constructs anything else — which is what would
 * restore models, run __wakeup and hit the database.
 */
final class RogueRestorationProbe
{
    public static int $constructed = 0;

    public function __wakeup(): void
    {
        self::$constructed++;
    }
}
