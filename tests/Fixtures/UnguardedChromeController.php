<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\Console\ServesConsoleChrome;
use ArtisanBuild\BuiltForCloud\Tests\ConsoleChromeRouteScan;

/**
 * The offence {@see ConsoleChromeRouteScan} exists to name: a controller
 * that declares itself part of the console chrome, mounted on a route
 * that is missing one or both halves of D14's seam.
 *
 * It is a fixture and nothing mounts it in `src/`. Its whole job is to
 * make the scan PROVE IT CAN FAIL — a route enumeration that has never
 * been shown to name anything is a check nobody has tested.
 */
final class UnguardedChromeController implements ServesConsoleChrome
{
    /**
     * @return array<string, bool>
     */
    public function __invoke(): array
    {
        return ['rendered' => true];
    }
}
