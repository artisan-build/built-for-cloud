<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Mcp;

use Attribute;
use ReflectionClass;

/** Declares the D14 data classification of one MCP tool. */
#[Attribute(Attribute::TARGET_CLASS)]
final readonly class ToolClassification
{
    public const string META_KEY = 'classification';

    public function __construct(public Classification $value) {}

    /**
     * @param  object|class-string  $tool
     */
    public static function of(object|string $tool): ?self
    {
        $attributes = (new ReflectionClass($tool))->getAttributes(self::class);

        return $attributes === [] ? null : $attributes[0]->newInstance();
    }
}
