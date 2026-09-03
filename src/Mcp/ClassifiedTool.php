<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Mcp;

use Laravel\Mcp\Server\Tool;

/** Laravel MCP tool base that advertises the package classification attribute. */
abstract class ClassifiedTool extends Tool
{
    use AdvertisesToolClassification;
}
