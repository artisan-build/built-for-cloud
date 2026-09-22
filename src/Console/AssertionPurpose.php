<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

/**
 * The doors a delegated assertion may be minted for. `Mcp` is the only
 * LIVE door: delegated MCP authentication requires it exactly. The
 * `ConsoleEntry` case names the delegated-entry door retired in v0.17.0
 * and is retained as a stable vocabulary value so a token minted for it
 * still VERIFIES and is refused by the MCP door as `purpose_mismatch`
 * — an audible, bounded audit reason — rather than degrading into an
 * `invalid_claims` refusal at the verifier.
 */
enum AssertionPurpose: string
{
    case ConsoleEntry = 'console-entry';
    case Mcp = 'mcp';
}
