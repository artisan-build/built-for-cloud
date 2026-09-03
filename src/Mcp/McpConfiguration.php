<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Mcp;

/** The deployment-declared MCP surface advertised by `/bfc/meta`. */
final class McpConfiguration
{
    public static function endpoint(): ?string
    {
        $path = config('built-for-cloud.mcp.path');

        if (! is_string($path) || preg_match('/^\/(?!\/)[^\s?#]*\z/u', $path) !== 1) {
            return null;
        }

        return $path;
    }

    public static function serves(): bool
    {
        return self::endpoint() !== null;
    }

    public static function delegated(): bool
    {
        return self::serves() && (bool) config('built-for-cloud.mcp.delegated', false);
    }
}
