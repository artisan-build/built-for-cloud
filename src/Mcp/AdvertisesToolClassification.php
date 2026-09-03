<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Mcp;

/**
 * Bridges {@see ToolClassification} into Laravel MCP's `tools/list` output.
 *
 * Use this trait on a `Laravel\Mcp\Server\Tool`. An undeclared tool emits the
 * conservative `content` default, but remains non-conforming until it carries
 * the attribute explicitly.
 *
 * Pinned by `tests/McpConformanceTest.php` — "accepts a server whose
 * tools declare and advertise the delegated contract".
 */
trait AdvertisesToolClassification
{
    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $declared = ToolClassification::of($this);
        $classification = $declared === null ? Classification::Content : $declared->value;

        $this->setMeta(ToolClassification::META_KEY, $classification->value);

        return parent::toArray();
    }
}
