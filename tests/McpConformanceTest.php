<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Mcp\AdvertisesToolClassification;
use ArtisanBuild\BuiltForCloud\Mcp\AdvertisesToolEffect;
use ArtisanBuild\BuiltForCloud\Mcp\Classification;
use ArtisanBuild\BuiltForCloud\Mcp\Effect;
use ArtisanBuild\BuiltForCloud\Mcp\RespectsEffectCeiling;
use ArtisanBuild\BuiltForCloud\Mcp\ToolClassification;
use ArtisanBuild\BuiltForCloud\Mcp\ToolEffect;
use ArtisanBuild\BuiltForCloud\Testing\ContractAssertions;
use Laravel\Mcp\Server;
use Laravel\Mcp\Server\Tool;
use Laravel\Mcp\Server\Tools\Annotations\IsReadOnly;
use PHPUnit\Framework\AssertionFailedError;

uses(ContractAssertions::class);

#[IsReadOnly]
#[ToolClassification(Classification::Metadata)]
#[ToolEffect(Effect::Read)]
final class ConformingMcpTool extends Tool
{
    use AdvertisesToolClassification, AdvertisesToolEffect, RespectsEffectCeiling;
}

#[ToolClassification(Classification::Content)]
#[ToolEffect(Effect::Write)]
final class MissingAnnotationMcpTool extends Tool
{
    use AdvertisesToolClassification, AdvertisesToolEffect, RespectsEffectCeiling;
}

#[IsReadOnly]
#[ToolEffect(Effect::Read)]
final class MissingClassificationMcpTool extends Tool
{
    use AdvertisesToolClassification, AdvertisesToolEffect, RespectsEffectCeiling;
}

#[IsReadOnly]
#[ToolClassification(Classification::Content)]
#[ToolEffect(Effect::Read)]
final class MissingMetaMcpTool extends Tool
{
    use AdvertisesToolEffect, RespectsEffectCeiling;
}

#[IsReadOnly]
#[ToolClassification(Classification::Metadata)]
final class MissingEffectMcpTool extends Tool
{
    use AdvertisesToolClassification, RespectsEffectCeiling;
}

#[IsReadOnly]
#[ToolClassification(Classification::Metadata)]
final class UndeclaredAdvertisedEffectMcpTool extends Tool
{
    use AdvertisesToolClassification, AdvertisesToolEffect, RespectsEffectCeiling;
}

#[IsReadOnly]
#[ToolClassification(Classification::Metadata)]
#[ToolEffect(Effect::Read)]
final class MissingEffectAdvertisementMcpTool extends Tool
{
    use AdvertisesToolClassification, RespectsEffectCeiling;
}

#[IsReadOnly]
#[ToolClassification(Classification::Metadata)]
#[ToolEffect(Effect::Read)]
final class MismatchedEffectAdvertisementMcpTool extends Tool
{
    /** @return array<string, mixed> */
    public function toArray(): array
    {
        $this->setMeta(ToolClassification::META_KEY, Classification::Metadata->value);
        $this->setMeta(ToolEffect::META_KEY, Effect::Write->value);

        return parent::toArray();
    }
}

#[IsReadOnly]
#[ToolClassification(Classification::Metadata)]
#[ToolEffect(Effect::Read)]
final class MissingEffectCeilingMcpTool extends Tool
{
    use AdvertisesToolClassification, AdvertisesToolEffect;
}

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

final class MissingEffectMcpServer extends Server
{
    protected array $tools = [MissingEffectMcpTool::class];
}

final class UndeclaredAdvertisedEffectMcpServer extends Server
{
    protected array $tools = [UndeclaredAdvertisedEffectMcpTool::class];
}

final class MissingEffectAdvertisementMcpServer extends Server
{
    protected array $tools = [MissingEffectAdvertisementMcpTool::class];
}

final class MismatchedEffectAdvertisementMcpServer extends Server
{
    protected array $tools = [MismatchedEffectAdvertisementMcpTool::class];
}

final class MissingEffectCeilingMcpServer extends Server
{
    protected array $tools = [MissingEffectCeilingMcpTool::class];
}

it('accepts a server whose tools declare and advertise the delegated contract', function (): void {
    $this->assertBuiltForCloudMcpDelegatedTools(ConformingMcpServer::class);

    $tool = app(ConformingMcpTool::class)->toArray();

    expect($tool['_meta']['classification'])->toBe('metadata')
        ->and($tool['_meta']['effect'])->toBe('read')
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

it('rejects a tool missing ToolEffect', function (): void {
    expect(fn () => $this->assertBuiltForCloudMcpDelegatedTools(MissingEffectMcpServer::class))
        ->toThrow(AssertionFailedError::class, MissingEffectMcpTool::class.' is missing ToolEffect.');
});

it('rejects a declared effect missing _meta.effect advertisement', function (): void {
    expect(fn () => $this->assertBuiltForCloudMcpDelegatedTools(MissingEffectAdvertisementMcpServer::class))
        ->toThrow(
            AssertionFailedError::class,
            MissingEffectAdvertisementMcpTool::class.' declares ToolEffect but does not advertise it in _meta.effect.',
        );
});

it('rejects a tool that does not enforce the request effect ceiling', function (): void {
    expect(fn () => $this->assertBuiltForCloudMcpDelegatedTools(MissingEffectCeilingMcpServer::class))
        ->toThrow(
            AssertionFailedError::class,
            MissingEffectCeilingMcpTool::class.' is missing RespectsEffectCeiling.',
        );
});

it('rejects a serialized effect that differs from its declaration', function (): void {
    expect(fn () => $this->assertBuiltForCloudMcpDelegatedTools(MismatchedEffectAdvertisementMcpServer::class))
        ->toThrow(
            AssertionFailedError::class,
            MismatchedEffectAdvertisementMcpTool::class." advertises _meta.effect as 'write', which does not match ToolEffect 'read'.",
        );
});

it('defaults an undeclared advertised effect to destructive while conformance still requires declaration', function (): void {
    $tool = app(UndeclaredAdvertisedEffectMcpTool::class)->toArray();

    expect($tool['_meta']['effect'])->toBe('destructive')
        ->and(fn () => $this->assertBuiltForCloudMcpDelegatedTools(UndeclaredAdvertisedEffectMcpServer::class))
        ->toThrow(
            AssertionFailedError::class,
            UndeclaredAdvertisedEffectMcpTool::class.' is missing ToolEffect.',
        );
});
