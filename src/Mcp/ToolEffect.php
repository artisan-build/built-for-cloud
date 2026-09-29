<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Mcp;

use Attribute;
use ReflectionClass;

/** Declares the state-changing effect of one MCP tool. */
#[Attribute(Attribute::TARGET_CLASS)]
final readonly class ToolEffect
{
    public const string META_KEY = 'effect';

    public function __construct(public Effect $value) {}

    /**
     * @param  object|class-string  $tool
     */
    public static function of(object|string $tool): ?self
    {
        $attributes = (new ReflectionClass($tool))->getAttributes(self::class);

        return $attributes === [] ? null : $attributes[0]->newInstance();
    }
}
