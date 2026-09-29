<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Mcp;

use Attribute;
use ReflectionClass;

/** Marks a destructive MCP tool for framework-enforced preview and confirmation. */
#[Attribute(Attribute::TARGET_CLASS)]
final readonly class TwoPhase
{
    public const string CONFIRM_ARGUMENT = 'confirm';

    public const string META_KEY = 'two_phase';

    public const string PREVIEW_METHOD = 'preview';

    /**
     * @param  object|class-string  $tool
     */
    public static function of(object|string $tool): ?self
    {
        $attributes = (new ReflectionClass($tool))->getAttributes(self::class);

        return $attributes === [] ? null : $attributes[0]->newInstance();
    }
}
