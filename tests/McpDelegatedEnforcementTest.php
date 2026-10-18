<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Console\ActingPrincipal;
use ArtisanBuild\BuiltForCloud\Console\ActingPrincipalResolver;
use ArtisanBuild\BuiltForCloud\Console\ConsoleRole;
use ArtisanBuild\BuiltForCloud\Console\RequestAssertion;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\Exceptions\DelegatedPrincipalUnsupported;
use ArtisanBuild\BuiltForCloud\Mcp\AdvertisesToolClassification;
use ArtisanBuild\BuiltForCloud\Mcp\AdvertisesToolEffect;
use ArtisanBuild\BuiltForCloud\Mcp\Classification;
use ArtisanBuild\BuiltForCloud\Mcp\Effect;
use ArtisanBuild\BuiltForCloud\Mcp\RespectsEffectCeiling;
use ArtisanBuild\BuiltForCloud\Mcp\ToolClassification;
use ArtisanBuild\BuiltForCloud\Mcp\ToolEffect;
use ArtisanBuild\BuiltForCloud\Testing\ContractAssertions;
use ArtisanBuild\BuiltForCloud\Testing\McpDelegatedEnforcement;
use Illuminate\Contracts\JsonSchema\JsonSchema;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Laravel\Mcp\Request;
use Laravel\Mcp\Response;
use Laravel\Mcp\Server;
use Laravel\Mcp\Server\Tool;
use Laravel\Mcp\Server\Tools\Annotations\IsReadOnly;
use PHPUnit\Framework\AssertionFailedError;

uses(RefreshDatabase::class, ContractAssertions::class);

final class DelegatedRowsFixture
{
    /** @var list<array{owner: int|string|null, value: string}> */
    public static array $rows = [];
}

#[IsReadOnly]
#[ToolClassification(Classification::Metadata)]
#[ToolEffect(Effect::Read)]
final class CanonicalDelegatedFixtureTool extends Tool
{
    use AdvertisesToolClassification, AdvertisesToolEffect, RespectsEffectCeiling;

    /** @var array<string, mixed> */
    public static array $arguments = [];

    /** @return array<string, mixed> */
    public function schema(JsonSchema $schema): array
    {
        return [
            'label' => $schema->string()->min(2)->required(),
            'limit' => $schema->integer()->min(3)->required(),
            'mode' => $schema->string()->enum(['first', 'second'])->required(),
            'flags' => $schema->array()->items($schema->boolean())->min(1)->required(),
            'scope' => $schema->object([
                'enabled' => $schema->boolean()->required(),
            ])->required(),
        ];
    }

    public function handle(Request $request): Response
    {
        app(ActingPrincipalResolver::class)->require(request());
        self::$arguments = $request->all();

        return Response::text('canonical-reached');
    }
}

#[IsReadOnly]
#[ToolClassification(Classification::Content)]
#[ToolEffect(Effect::Read)]
final class ScopedDelegatedRowsFixtureTool extends Tool
{
    use AdvertisesToolClassification, AdvertisesToolEffect, RespectsEffectCeiling;

    public function handle(): Response
    {
        $principal = app(ActingPrincipalResolver::class)->require(request());
        $rows = array_values(array_filter(
            DelegatedRowsFixture::$rows,
            static fn (array $row): bool => $row['owner'] === $principal->identifier(),
        ));

        return Response::json($rows);
    }
}

final class CanonicalDelegatedFixtureServer extends Server
{
    protected array $tools = [CanonicalDelegatedFixtureTool::class, ScopedDelegatedRowsFixtureTool::class];
}

#[IsReadOnly]
#[ToolClassification(Classification::Metadata)]
#[ToolEffect(Effect::Read)]
final class CredentialOnlyDelegatedFixtureTool extends Tool
{
    use AdvertisesToolClassification, AdvertisesToolEffect, RespectsEffectCeiling;

    public function handle(): Response
    {
        if (! request()->user() instanceof Credential) {
            throw new DelegatedPrincipalUnsupported('Fixture accepts direct credentials only.');
        }

        return Response::text('credential-only-reached');
    }
}

final class CredentialOnlyDelegatedFixtureServer extends Server
{
    protected array $tools = [CredentialOnlyDelegatedFixtureTool::class];
}

#[IsReadOnly]
#[ToolClassification(Classification::Metadata)]
#[ToolEffect(Effect::Read)]
final class UnauthenticatedRegistrationFixtureTool extends Tool
{
    use AdvertisesToolClassification, AdvertisesToolEffect, RespectsEffectCeiling;

    public function shouldRegister(): bool
    {
        return request()->user() instanceof Credential;
    }

    public function handle(): Response
    {
        return Response::text('should-not-register');
    }
}

final class UnauthenticatedRegistrationFixtureServer extends Server
{
    protected array $tools = [UnauthenticatedRegistrationFixtureTool::class];
}

#[IsReadOnly]
#[ToolClassification(Classification::Metadata)]
#[ToolEffect(Effect::Read)]
final class WrongPrincipalProjectionFixtureTool extends Tool
{
    use AdvertisesToolClassification, AdvertisesToolEffect, RespectsEffectCeiling;

    public function handle(): Response
    {
        $wrongActor = consoleActor(subject: 'wrong-projected-actor', role: ConsoleRole::Member);
        RequestAssertion::publish(
            request(),
            $wrongActor,
            consoleAssertionFor(subject: 'wrong-projected-actor', role: ConsoleRole::Member),
        );
        app(ActingPrincipalResolver::class)->require(request());

        return Response::text('wrong-principal-reached');
    }
}

final class WrongPrincipalProjectionFixtureServer extends Server
{
    protected array $tools = [WrongPrincipalProjectionFixtureTool::class];
}

#[IsReadOnly]
#[ToolClassification(Classification::Metadata)]
#[ToolEffect(Effect::Read)]
final class ArbitraryStringRefusalFixtureTool extends Tool
{
    use AdvertisesToolClassification, AdvertisesToolEffect, RespectsEffectCeiling;

    public function handle(): Response
    {
        return Response::error('A deliberately unrelated fixture string.');
    }
}

final class ArbitraryStringRefusalFixtureServer extends Server
{
    protected array $tools = [ArbitraryStringRefusalFixtureTool::class];
}

#[IsReadOnly]
#[ToolClassification(Classification::Metadata)]
#[ToolEffect(Effect::Read)]
final class ObservedApplicationErrorFixtureTool extends Tool
{
    use AdvertisesToolClassification, AdvertisesToolEffect, RespectsEffectCeiling;

    public function handle(): Response
    {
        app(ActingPrincipalResolver::class)->require(request());

        return Response::error('A deliberately unrelated fixture string.');
    }
}

final class ObservedApplicationErrorFixtureServer extends Server
{
    protected array $tools = [ObservedApplicationErrorFixtureTool::class];
}

#[IsReadOnly]
#[ToolClassification(Classification::Metadata)]
#[ToolEffect(Effect::Read)]
final class UnsynthesizableSchemaFixtureTool extends Tool
{
    use AdvertisesToolClassification, AdvertisesToolEffect, RespectsEffectCeiling;

    /** @return array<string, mixed> */
    public function schema(JsonSchema $schema): array
    {
        return ['opaque' => $schema->string()->pattern('/^[A-Z]{3}[0-9]{4}$/')->required()];
    }

    public function handle(): Response
    {
        app(ActingPrincipalResolver::class)->require(request());

        return Response::text('should-not-be-guessed');
    }
}

final class UnsynthesizableSchemaFixtureServer extends Server
{
    protected array $tools = [UnsynthesizableSchemaFixtureTool::class];
}

beforeEach(function (): void {
    DelegatedRowsFixture::$rows = [];
    CanonicalDelegatedFixtureTool::$arguments = [];
});

it('registers and invokes every expected tool under a verified delegated assertion', function (): void {
    $result = McpDelegatedEnforcement::probe(CanonicalDelegatedFixtureServer::class);

    expect($result['tools'])->toBe([
        CanonicalDelegatedFixtureTool::class,
        ScopedDelegatedRowsFixtureTool::class,
    ])->and($result['invoked'])->toBe([
        CanonicalDelegatedFixtureTool::class,
        ScopedDelegatedRowsFixtureTool::class,
    ])->and($result['negative_authorization'])->toBe('absent')
        ->and($result['violations'])->toBe([])
        ->and(CanonicalDelegatedFixtureTool::$arguments)->toBe([
            'label' => 'xx',
            'limit' => 3,
            'mode' => 'first',
            'flags' => [false],
            'scope' => ['enabled' => false],
        ]);

    $admin = McpDelegatedEnforcement::probe(CanonicalDelegatedFixtureServer::class, ConsoleRole::Admin);
    expect($admin['violations'])->toBe([]);

    $this->assertBuiltForCloudMcpDelegatedEnforcement(
        CanonicalDelegatedFixtureServer::class,
        [CanonicalDelegatedFixtureTool::class, ScopedDelegatedRowsFixtureTool::class],
    );
});

it('runs and records the opt-in second-subject authorization case', function (): void {
    $negative = static function (ActingPrincipal $first, ActingPrincipal $second, Closure $invoke): void {
        expect($second->identifier())->not->toBe($first->identifier());
        DelegatedRowsFixture::$rows[] = ['owner' => $first->identifier(), 'value' => 'first-only'];

        $response = $invoke(ScopedDelegatedRowsFixtureTool::class);
        expect($response)->toBeInstanceOf(Response::class)
            ->and(json_decode((string) $response->content(), true, flags: JSON_THROW_ON_ERROR))->toBe([]);
    };

    $result = McpDelegatedEnforcement::probe(
        CanonicalDelegatedFixtureServer::class,
        ConsoleRole::Member,
        $negative,
    );

    expect($result['negative_authorization'])->toBe('passed')
        ->and($result['violations'])->toBe([]);

    McpDelegatedEnforcement::assertHonors(
        CanonicalDelegatedFixtureServer::class,
        [CanonicalDelegatedFixtureTool::class, ScopedDelegatedRowsFixtureTool::class],
        ConsoleRole::Member,
        $negative,
    );
});

it('discriminates every delegated identity failure class structurally', function (
    string $server,
    string $tool,
    string $resultKey,
    string $expected,
): void {
    $result = McpDelegatedEnforcement::probe($server);

    expect($result[$resultKey][$tool] ?? null)->toBe($expected)
        ->and($result['violations'])->not->toBe([]);
})->with([
    'credential-only resolver' => [
        CredentialOnlyDelegatedFixtureServer::class,
        CredentialOnlyDelegatedFixtureTool::class,
        'refusals',
        DelegatedPrincipalUnsupported::class,
    ],
    'wrong-principal projection' => [
        WrongPrincipalProjectionFixtureServer::class,
        WrongPrincipalProjectionFixtureTool::class,
        'principal_mismatches',
        'different-principal',
    ],
    'arbitrary-string refusal' => [
        ArbitraryStringRefusalFixtureServer::class,
        ArbitraryStringRefusalFixtureTool::class,
        'errors',
        'error-response-without-principal',
    ],
]);

it('rejects unauthenticated zero-registration without a vacuous pass', function (): void {
    $result = McpDelegatedEnforcement::probe(UnauthenticatedRegistrationFixtureServer::class);

    expect($result['tools'])->toBe([])
        ->and($result['invoked'])->toBe([])
        ->and($result['violations'])->toContain('no-tools-registered-under-delegated-assertion');
});

it('does not infer an identity refusal from application error text', function (): void {
    $result = McpDelegatedEnforcement::probe(ObservedApplicationErrorFixtureServer::class);

    expect($result['invoked'])->toBe([ObservedApplicationErrorFixtureTool::class])
        ->and($result['refusals'])->toBe([])
        ->and($result['errors'])->toBe([])
        ->and($result['violations'])->toBe([]);
});

it('reports an unsynthesizable tool as unreached instead of skipping it', function (): void {
    $result = McpDelegatedEnforcement::probe(UnsynthesizableSchemaFixtureServer::class);

    expect($result['invoked'])->toBe([])
        ->and($result['unreached'])->toBe([
            UnsynthesizableSchemaFixtureTool::class => 'property-opaque:unsupported-string-pattern',
        ])
        ->and($result['violations'])->toContain(
            'tool-unreached:'.UnsynthesizableSchemaFixtureTool::class.':property-opaque:unsupported-string-pattern',
        );

    $covered = McpDelegatedEnforcement::probe(
        UnsynthesizableSchemaFixtureServer::class,
        arguments: [UnsynthesizableSchemaFixtureTool::class => ['opaque' => 'ABC1234']],
    );

    expect($covered['invoked'])->toBe([UnsynthesizableSchemaFixtureTool::class])
        ->and($covered['unreached'])->toBe([])
        ->and($covered['violations'])->toBe([]);
});

it('requires a non-empty exact expected tool list', function (): void {
    expect(fn () => McpDelegatedEnforcement::assertHonors(CanonicalDelegatedFixtureServer::class, []))
        ->toThrow(AssertionFailedError::class, 'non-empty expected tool list')
        ->and(fn () => McpDelegatedEnforcement::assertHonors(
            CanonicalDelegatedFixtureServer::class,
            [CanonicalDelegatedFixtureTool::class],
        ))->toThrow(AssertionFailedError::class, 'unexpected-tool:'.ScopedDelegatedRowsFixtureTool::class);
});
