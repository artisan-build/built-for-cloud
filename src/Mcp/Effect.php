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

    public function allows(self $effect): bool
    {
        return $this->rank() >= $effect->rank();
    }

    private function rank(): int
    {
        return match ($this) {
            self::Read => 0,
            self::Write => 1,
            self::Destructive => 2,
        };
    }
}
