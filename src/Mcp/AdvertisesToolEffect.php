<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Mcp;

/**
 * Bridges {@see ToolEffect} into Laravel MCP's `tools/list` output.
 *
 * Use this trait on a `Laravel\Mcp\Server\Tool`. An undeclared tool emits the
 * fail-closed `destructive` default, but remains non-conforming until it carries
 * the attribute explicitly.
 *
 * Pinned by `tests/McpConformanceTest.php` — "defaults an undeclared
 * advertised effect to destructive while conformance still requires declaration".
 *
 * @phpstan-ignore trait.unused (the supported seam for consuming products and the conformance fixtures)
 */
trait AdvertisesToolEffect
{
    use AdvertisesToolClassification;

    private function advertiseToolEffect(): void
    {
        $declared = ToolEffect::of($this);
        $effect = $declared === null ? Effect::Destructive : $declared->value;

        $this->setMeta(ToolEffect::META_KEY, $effect->value);
    }
}
