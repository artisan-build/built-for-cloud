<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use ArtisanBuild\BuiltForCloud\Mcp\Effect;
use ArtisanBuild\BuiltForCloud\Mcp\RequestEffectCeiling;
use ArtisanBuild\BuiltForCloud\Mcp\RespectsEffectCeiling;
use ArtisanBuild\BuiltForCloud\Mcp\ToolClassification;
use ArtisanBuild\BuiltForCloud\Mcp\ToolEffect;
use ArtisanBuild\BuiltForCloud\Mcp\TwoPhase;
use Illuminate\Http\Request;
use Illuminate\JsonSchema\JsonSchemaTypeFactory;
use Laravel\Mcp\Server;
use Laravel\Mcp\Server\Tool;
use Laravel\Mcp\Server\Tools\Annotations\IsDestructive;
use Laravel\Mcp\Server\Tools\Annotations\IsIdempotent;
use Laravel\Mcp\Server\Tools\Annotations\IsReadOnly;
use Laravel\Mcp\Server\Tools\ToolSearch;
use Laravel\Mcp\Server\Transport\FakeTransporter;
use PHPUnit\Framework\Assert;
use ReflectionAttribute;
use ReflectionClass;
use ReflectionProperty;

/**
 * Checks the registered, currently eligible tools of one Laravel MCP server.
 * Every tool must carry a behavioural annotation, explicitly declare a D14
 * classification and an effect, enforce the request effect ceiling, and
 * serialize both declarations into `_meta`.
 *
 * This does not inspect tools absent from the server's registry, tools made
 * ineligible by the current application state, response bodies, tool
 * implementations, whether declarations truthfully describe behaviour, or
 * whether callers are constrained by them. It proves declaration and wire
 * propagation, not semantic honesty or enforcement.
 *
 * Pinned by `tests/McpConformanceTest.php` — "names every offending
 * tool and the contract leg it violates".
 */
final class McpDelegatedTools
{
    /**
     * @param  class-string<Server>  $serverClass
     */
    public static function assertConforms(string $serverClass): void
    {
        $result = self::discover($serverClass);

        Assert::assertSame(
            [],
            $result['violations'],
            "The MCP server cannot advertise mcp-delegated:\n".implode("\n", $result['violations']),
        );
    }

    /**
     * @param  class-string<Server>  $serverClass
     * @return array{tools: list<string>, violations: list<string>}
     */
    public static function discover(string $serverClass): array
    {
        $server = app()->make($serverClass, ['transport' => new FakeTransporter]);

        Assert::assertInstanceOf(Server::class, $server, $serverClass.' is not a Laravel MCP server.');

        // Production calls boot before it creates the context. Starting with
        // the fake transport exercises the same dynamic registrations.
        $server->start();

        $offences = [];
        $tools = [];
        $request = app('request');

        Assert::assertInstanceOf(Request::class, $request);

        /** @var array<int|string, Tool|class-string<Tool>|array<int, Tool|class-string<Tool>>> $rawTools */
        $rawTools = (new ReflectionProperty(Server::class, 'tools'))->getValue($server);
        $groupedTools = $rawTools[ToolSearch::class] ?? [];

        if (is_array($groupedTools)) {
            foreach ($groupedTools as $groupedTool) {
                $tool = is_string($groupedTool) ? app()->make($groupedTool) : $groupedTool;

                if ($tool instanceof Tool && TwoPhase::of($tool) !== null) {
                    $offences[] = $tool::class.' declares TwoPhase inside a ToolSearch group, whose execute_tools path bypasses the two-phase guard.';
                }
            }
        }

        $registered = RequestEffectCeiling::run(
            $request,
            Effect::Destructive,
            static fn () => $server->createContext()->tools(),
        );

        foreach ($registered as $tool) {
            $tools[] = $tool::class;
            self::inspect($tool, $offences);
        }

        sort($tools);
        sort($offences);

        return [
            'tools' => array_values(array_unique($tools)),
            'violations' => array_values(array_unique($offences)),
        ];
    }

    /**
     * @param  list<string>  $offences
     */
    private static function inspect(Tool $tool, array &$offences): void
    {
        $reflection = new ReflectionClass($tool);
        $name = $tool::class;
        $annotation = false;

        foreach ([IsReadOnly::class, IsDestructive::class, IsIdempotent::class] as $attribute) {
            if ($reflection->getAttributes($attribute, ReflectionAttribute::IS_INSTANCEOF) !== []) {
                $annotation = true;
                break;
            }
        }

        if (! $annotation) {
            $offences[] = $name.' is missing IsReadOnly, IsDestructive, or IsIdempotent.';
        }

        if (! in_array(RespectsEffectCeiling::class, class_uses_recursive($tool), true)) {
            $offences[] = $name.' is missing RespectsEffectCeiling.';
        }

        $classification = ToolClassification::of($tool);

        if ($classification === null) {
            $offences[] = $name.' is missing ToolClassification.';
        }

        $effect = ToolEffect::of($tool);

        if ($effect === null) {
            $offences[] = $name.' is missing ToolEffect.';
        }

        $twoPhase = TwoPhase::of($tool);

        if ($twoPhase !== null && $effect?->value !== Effect::Destructive) {
            $offences[] = $name.' declares TwoPhase without a destructive ToolEffect.';
        }

        if ($twoPhase !== null && ! is_callable([$tool, TwoPhase::PREVIEW_METHOD])) {
            $offences[] = $name.' declares TwoPhase without a public preview method.';
        }

        if ($twoPhase !== null
            && array_key_exists(TwoPhase::CONFIRM_ARGUMENT, $tool->schema(new JsonSchemaTypeFactory))) {
            $offences[] = $name.' declares the reserved top-level confirm field in its application schema.';
        }

        $serialized = $tool->toArray();
        $advertised = $serialized['_meta'][ToolClassification::META_KEY] ?? null;

        if ($classification !== null && $advertised !== $classification->value->value) {
            $offences[] = $name.' declares ToolClassification but does not advertise it in _meta.classification.';
        }

        $metadata = $serialized['_meta'] ?? [];

        if ($effect !== null && ! array_key_exists(ToolEffect::META_KEY, $metadata)) {
            $offences[] = $name.' declares ToolEffect but does not advertise it in _meta.effect.';
        } elseif ($effect !== null && $metadata[ToolEffect::META_KEY] !== $effect->value->value) {
            $offences[] = sprintf(
                '%s advertises _meta.effect as %s, which does not match ToolEffect %s.',
                $name,
                var_export($metadata[ToolEffect::META_KEY], true),
                var_export($effect->value->value, true),
            );
        }

        if ($twoPhase !== null
            && (($metadata[TwoPhase::META_KEY]['confirmationArgument'] ?? null) !== TwoPhase::CONFIRM_ARGUMENT
                || ! array_key_exists(TwoPhase::CONFIRM_ARGUMENT, (array) ($serialized['inputSchema']['properties'] ?? [])))) {
            $offences[] = $name.' declares TwoPhase but does not advertise its confirmation protocol.';
        }
    }
}
