<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

/** The only two doors a delegated assertion may be minted for. */
enum AssertionPurpose: string
{
    case ConsoleEntry = 'console-entry';
    case Mcp = 'mcp';
}
