<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Mcp\AdvertisesToolClassification;
use ArtisanBuild\BuiltForCloud\Mcp\Classification;
use ArtisanBuild\BuiltForCloud\Mcp\ToolClassification;
use ArtisanBuild\BuiltForCloud\Testing\ContractAssertions;
use Laravel\Mcp\Server;
use Laravel\Mcp\Server\Tool;
use Laravel\Mcp\Server\Tools\Annotations\IsReadOnly;
use PHPUnit\Framework\AssertionFailedError;

uses(ContractAssertions::class);

#[IsReadOnly]
#[ToolClassification(Classification::Metadata)]
final class ConformingMcpTool extends Tool
{
    use AdvertisesToolClassification;
}

#[ToolClassification(Classification::Content)]
final class MissingAnnotationMcpTool extends Tool
{
    use AdvertisesToolClassification;
}

#[IsReadOnly]
final class MissingClassificationMcpTool extends Tool
{
    use AdvertisesToolClassification;
}

#[IsReadOnly]
#[ToolClassification(Classification::Content)]
final class MissingMetaMcpTool extends Tool {}

final class ConformingMcpServer extends Server
{
    protected array $tools = [ConformingMcpTool::class];
}

final class OffendingMcpServer extends Server
{
    protected array $tools = [
        MissingAnnotationMcpTool::class,
        MissingClassificationMcpTool::class,
        MissingMetaMcpTool::class,
    ];
}

it('accepts a server whose tools declare and advertise the delegated contract', function (): void {
    $this->assertBuiltForCloudMcpDelegatedTools(ConformingMcpServer::class);

    $tool = app(ConformingMcpTool::class)->toArray();

    expect($tool['_meta']['classification'])->toBe('metadata')
        ->and($tool['annotations']['readOnlyHint'])->toBeTrue();
});

it('names every offending tool and the contract leg it violates', function (): void {
    try {
        $this->assertBuiltForCloudMcpDelegatedTools(OffendingMcpServer::class);
    } catch (AssertionFailedError $failure) {
        expect($failure->getMessage())
            ->toContain(MissingAnnotationMcpTool::class)
            ->toContain('missing IsReadOnly, IsDestructive, or IsIdempotent')
            ->toContain(MissingClassificationMcpTool::class)
            ->toContain('missing ToolClassification')
            ->toContain(MissingMetaMcpTool::class)
            ->toContain('does not advertise it in _meta.classification');

        return;
    }

    $this->fail('The offending MCP server passed the delegated-tool conformance assertion.');
});
