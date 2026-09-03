<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Mcp;

/** The D14 data boundary a relayed MCP tool declares. */
enum Classification: string
{
    case Metadata = 'metadata';
    case Content = 'content';
}
