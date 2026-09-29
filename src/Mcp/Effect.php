<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Mcp;

use ArtisanBuild\BuiltForCloudContracts\Mcp\Effect as ContractsEffect;

/** The state-changing effect a relayed MCP tool declares. */
enum Effect: string
{
    case Read = 'read';
    case Write = 'write';
    case Destructive = 'destructive';

    /**
     * @return list<string>
     */
    public static function values(): array
    {
        return array_column(ContractsEffect::cases(), 'value');
    }
}
