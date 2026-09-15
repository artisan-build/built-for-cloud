<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use ArtisanBuild\BuiltForCloud\Mcp\ToolClassification;
use Laravel\Mcp\Server;
use Laravel\Mcp\Server\Tool;
use Laravel\Mcp\Server\Tools\Annotations\IsDestructive;
use Laravel\Mcp\Server\Tools\Annotations\IsIdempotent;
use Laravel\Mcp\Server\Tools\Annotations\IsReadOnly;
use Laravel\Mcp\Server\Transport\FakeTransporter;
use PHPUnit\Framework\Assert;
use ReflectionAttribute;
use ReflectionClass;

/**
 * Checks the registered, currently eligible tools of one Laravel MCP server.
 * Every tool must carry a behavioural annotation, explicitly declare a D14
 * classification, and serialize that declaration into `_meta.classification`.
 *
 * This does not inspect tools absent from the server's registry, tools made
 * ineligible by the current application state, response bodies, tool
 * implementations, or whether an annotation truthfully describes behaviour.
 * It proves declaration and wire propagation, not semantic honesty.
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

        foreach ($server->createContext()->tools() as $tool) {
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

        $classification = ToolClassification::of($tool);

        if ($classification === null) {
            $offences[] = $name.' is missing ToolClassification.';
        }

        $serialized = $tool->toArray();
        $advertised = $serialized['_meta'][ToolClassification::META_KEY] ?? null;

        if ($classification !== null && $advertised !== $classification->value->value) {
            $offences[] = $name.' declares ToolClassification but does not advertise it in _meta.classification.';
        }
    }
}
