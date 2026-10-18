<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Console\ActingPrincipal;
use ArtisanBuild\BuiltForCloud\Console\ActingPrincipalResolver;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKey;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyring;
use ArtisanBuild\BuiltForCloud\Console\ConsoleRole;
use ArtisanBuild\BuiltForCloud\Console\DelegatedActor;
use ArtisanBuild\BuiltForCloud\Console\DelegatedClaims;
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
use ArtisanBuild\BuiltForCloud\Testing\McpDelegatedAssertionFixture;
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

    public static bool $authorizationReached = false;

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

    public function handle(Request $input): Response
    {
        app(ActingPrincipalResolver::class)->require(request());
        self::$arguments = $input->all();

        if ($input->all() !== [
            'label' => 'xx',
            'limit' => 3,
            'mode' => 'first',
            'flags' => [false],
            'scope' => ['enabled' => false],
        ]) {
            return Response::error('The synthesized arguments did not reach authorization.');
        }

        self::$authorizationReached = true;

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

#[IsReadOnly]
#[ToolClassification(Classification::Metadata)]
#[ToolEffect(Effect::Read)]
final class NumberMultipleFixtureTool extends Tool
{
    use AdvertisesToolClassification, AdvertisesToolEffect, RespectsEffectCeiling;

    public static mixed $received = null;

    public static bool $authorizationReached = false;

    /** @return array<string, mixed> */
    public function schema(JsonSchema $schema): array
    {
        return ['amount' => $schema->number()->min(1)->max(5)->multipleOf(2)->required()];
    }

    public function handle(Request $input): Response
    {
        app(ActingPrincipalResolver::class)->require(request());
        self::$received = $input->get('amount');

        if ($input->get('amount') !== 2.0) {
            return Response::error('The multiple did not reach authorization.');
        }

        self::$authorizationReached = true;

        return Response::text('number-multiple-reached');
    }
}

final class NumberMultipleFixtureServer extends Server
{
    protected array $tools = [NumberMultipleFixtureTool::class];
}

#[IsReadOnly]
#[ToolClassification(Classification::Metadata)]
#[ToolEffect(Effect::Read)]
final class UniqueArrayFixtureTool extends Tool
{
    use AdvertisesToolClassification, AdvertisesToolEffect, RespectsEffectCeiling;

    /** @var list<bool> */
    public static array $received = [];

    public static bool $authorizationReached = false;

    /** @return array<string, mixed> */
    public function schema(JsonSchema $schema): array
    {
        return [
            'flags' => $schema->array()->items($schema->boolean())->min(2)->max(2)->unique()->required(),
        ];
    }

    public function handle(Request $input): Response
    {
        app(ActingPrincipalResolver::class)->require(request());
        $flags = $input->get('flags');
        self::$received = is_array($flags) ? $flags : [];

        if ($flags !== [false, true]) {
            return Response::error('The unique flags did not reach authorization.');
        }

        self::$authorizationReached = true;

        return Response::text('unique-array-reached');
    }
}

final class UniqueArrayFixtureServer extends Server
{
    protected array $tools = [UniqueArrayFixtureTool::class];
}

#[IsReadOnly]
#[ToolClassification(Classification::Metadata)]
#[ToolEffect(Effect::Read)]
final class ClosedObjectFixtureTool extends Tool
{
    use AdvertisesToolClassification, AdvertisesToolEffect, RespectsEffectCeiling;

    public static bool $authorizationReached = false;

    /** @return array<string, mixed> */
    public function schema(JsonSchema $schema): array
    {
        return [
            'scope' => $schema->object([
                'enabled' => $schema->boolean()->required(),
            ])->withoutAdditionalProperties()->required(),
        ];
    }

    public function handle(Request $input): Response
    {
        app(ActingPrincipalResolver::class)->require(request());

        if ($input->get('scope') !== ['enabled' => false]) {
            return Response::error('The closed object did not reach authorization.');
        }

        self::$authorizationReached = true;

        return Response::text('closed-object-reached');
    }
}

final class ClosedObjectFixtureServer extends Server
{
    protected array $tools = [ClosedObjectFixtureTool::class];
}

#[IsReadOnly]
#[ToolClassification(Classification::Metadata)]
#[ToolEffect(Effect::Read)]
final class ImpossibleBoundsFixtureTool extends Tool
{
    use AdvertisesToolClassification, AdvertisesToolEffect, RespectsEffectCeiling;

    /** @return array<string, mixed> */
    public function schema(JsonSchema $schema): array
    {
        return [
            'items' => $schema->array()->items($schema->string())->min(3)->max(2)->required(),
            'code' => $schema->string()->min(4)->max(3)->required(),
        ];
    }

    public function handle(): Response
    {
        app(ActingPrincipalResolver::class)->require(request());

        return Response::text('impossible-bounds-reached');
    }
}

final class ImpossibleBoundsFixtureServer extends Server
{
    protected array $tools = [ImpossibleBoundsFixtureTool::class];
}

#[IsReadOnly]
#[ToolClassification(Classification::Metadata)]
#[ToolEffect(Effect::Read)]
final class ImpossibleStringBoundsFixtureTool extends Tool
{
    use AdvertisesToolClassification, AdvertisesToolEffect, RespectsEffectCeiling;

    /** @return array<string, mixed> */
    public function schema(JsonSchema $schema): array
    {
        return ['code' => $schema->string()->min(4)->max(3)->required()];
    }

    public function handle(): Response
    {
        app(ActingPrincipalResolver::class)->require(request());

        return Response::text('impossible-string-bounds-reached');
    }
}

final class ImpossibleStringBoundsFixtureServer extends Server
{
    protected array $tools = [ImpossibleStringBoundsFixtureTool::class];
}

#[IsReadOnly]
#[ToolEffect(Effect::Read)]
final class DeclarationOffendingEnforcementFixtureTool extends Tool
{
    use AdvertisesToolClassification, AdvertisesToolEffect, RespectsEffectCeiling;

    public function handle(): Response
    {
        app(ActingPrincipalResolver::class)->require(request());

        return Response::text('declaration-offender-reached');
    }
}

final class DeclarationOffendingEnforcementFixtureServer extends Server
{
    protected array $tools = [DeclarationOffendingEnforcementFixtureTool::class];
}

#[IsReadOnly]
#[ToolClassification(Classification::Metadata)]
#[ToolEffect(Effect::Read)]
final class IdentityBlindSuccessFixtureTool extends Tool
{
    use AdvertisesToolClassification, AdvertisesToolEffect, RespectsEffectCeiling;

    public function handle(): Response
    {
        return Response::text('identity-blind-success');
    }
}

final class IdentityBlindSuccessFixtureServer extends Server
{
    protected array $tools = [IdentityBlindSuccessFixtureTool::class];
}

#[IsReadOnly]
#[ToolClassification(Classification::Metadata)]
#[ToolEffect(Effect::Read)]
final class ObservationMismatchFixtureTool extends Tool
{
    use AdvertisesToolClassification, AdvertisesToolEffect, RespectsEffectCeiling;

    public static string $mode = 'role';

    public function handle(): Response
    {
        $actual = app(ActingPrincipalResolver::class)->require(request());
        $observer = request()->attributes->get(ActingPrincipalResolver::OBSERVER_ATTRIBUTE);
        $actor = $actual->principal;

        if (! is_callable($observer) || ! $actor instanceof DelegatedActor) {
            return Response::error('The observation fixture was not initialized.');
        }

        $observer(self::$mode === 'role'
            ? ActingPrincipal::delegatedRequest($actor, new DelegatedClaims(
                displayName: 'Wrong Role',
                role: ConsoleRole::Admin,
                onBehalfOf: null,
            ))
            : ActingPrincipal::local(null, $actor));

        return Response::text('observation-mismatch-reached');
    }
}

final class ObservationMismatchFixtureServer extends Server
{
    protected array $tools = [ObservationMismatchFixtureTool::class];
}

#[IsReadOnly]
#[ToolClassification(Classification::Metadata)]
#[ToolEffect(Effect::Read)]
final class DifferentRawPrincipalFixtureTool extends Tool
{
    use AdvertisesToolClassification, AdvertisesToolEffect, RespectsEffectCeiling;

    public function handle(): Response
    {
        request()->user();
        app(ActingPrincipalResolver::class)->require(request());

        return Response::text('different-raw-principal-reached');
    }
}

final class DifferentRawPrincipalFixtureServer extends Server
{
    protected array $tools = [DifferentRawPrincipalFixtureTool::class];

    protected function boot(): void
    {
        $actor = consoleActor(subject: 'different-raw-principal', role: ConsoleRole::Member);
        request()->setUserResolver(static fn (): DelegatedActor => $actor);
    }
}

beforeEach(function (): void {
    DelegatedRowsFixture::$rows = [];
    CanonicalDelegatedFixtureTool::$arguments = [];
    CanonicalDelegatedFixtureTool::$authorizationReached = false;
    NumberMultipleFixtureTool::$received = null;
    NumberMultipleFixtureTool::$authorizationReached = false;
    UniqueArrayFixtureTool::$received = [];
    UniqueArrayFixtureTool::$authorizationReached = false;
    ClosedObjectFixtureTool::$authorizationReached = false;
    ObservationMismatchFixtureTool::$mode = 'role';
    app()->forgetInstance('mcp.request');
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
        ->and(CanonicalDelegatedFixtureTool::$authorizationReached)->toBeTrue()
        ->and(CanonicalDelegatedFixtureTool::$arguments)->toBe([
            'label' => 'xx',
            'limit' => 3,
            'mode' => 'first',
            'flags' => [false],
            'scope' => ['enabled' => false],
        ])
        ->and(app()->bound('mcp.request'))->toBeFalse();

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

it('restores a prior MCP request binding after successful and exceptional tool calls', function (): void {
    $prior = new Request(['prior' => 'unchanged']);
    app()->instance('mcp.request', $prior);

    $success = McpDelegatedEnforcement::probe(CanonicalDelegatedFixtureServer::class);
    expect($success['violations'])->toBe([])
        ->and(app('mcp.request'))->toBe($prior)
        ->and(app('mcp.request')->all())->toBe(['prior' => 'unchanged']);

    $refusal = McpDelegatedEnforcement::probe(CredentialOnlyDelegatedFixtureServer::class);
    expect($refusal['refusals'])->toHaveKey(CredentialOnlyDelegatedFixtureTool::class)
        ->and(app('mcp.request'))->toBe($prior)
        ->and(app('mcp.request')->all())->toBe(['prior' => 'unchanged']);
});

it('synthesizes a schema-valid number multiple before authorization', function (): void {
    $result = McpDelegatedEnforcement::probe(NumberMultipleFixtureServer::class);

    expect($result['violations'])->toBe([])
        ->and(NumberMultipleFixtureTool::$received)->toBe(2.0)
        ->and(NumberMultipleFixtureTool::$authorizationReached)->toBeTrue();
});

it('fails closed on unique arrays until a schema-valid reviewed override is supplied', function (): void {
    $unreached = McpDelegatedEnforcement::probe(UniqueArrayFixtureServer::class);
    expect($unreached['unreached'])->toBe([
        UniqueArrayFixtureTool::class => 'property-flags:unsupported-unique-items',
    ])->and(UniqueArrayFixtureTool::$authorizationReached)->toBeFalse();

    $invalid = McpDelegatedEnforcement::probe(
        UniqueArrayFixtureServer::class,
        arguments: [UniqueArrayFixtureTool::class => ['flags' => [false, false]]],
    );
    expect($invalid['unreached'])->toBe([
        UniqueArrayFixtureTool::class => 'override-invalid:property-flags:array-items-not-unique',
    ])->and(UniqueArrayFixtureTool::$authorizationReached)->toBeFalse();

    $tooMany = McpDelegatedEnforcement::probe(
        UniqueArrayFixtureServer::class,
        arguments: [UniqueArrayFixtureTool::class => ['flags' => [false, true, false]]],
    );
    expect($tooMany['unreached'])->toBe([
        UniqueArrayFixtureTool::class => 'override-invalid:property-flags:array-above-max-items',
    ])->and(UniqueArrayFixtureTool::$authorizationReached)->toBeFalse();

    $covered = McpDelegatedEnforcement::probe(
        UniqueArrayFixtureServer::class,
        arguments: [UniqueArrayFixtureTool::class => ['flags' => [false, true]]],
    );
    expect($covered['violations'])->toBe([])
        ->and(UniqueArrayFixtureTool::$received)->toBe([false, true])
        ->and(UniqueArrayFixtureTool::$authorizationReached)->toBeTrue();
});

it('honors closed object constraints for synthesis and reviewed overrides', function (): void {
    $synthesized = McpDelegatedEnforcement::probe(ClosedObjectFixtureServer::class);
    expect($synthesized['violations'])->toBe([])
        ->and(ClosedObjectFixtureTool::$authorizationReached)->toBeTrue();

    ClosedObjectFixtureTool::$authorizationReached = false;
    $invalid = McpDelegatedEnforcement::probe(
        ClosedObjectFixtureServer::class,
        arguments: [
            ClosedObjectFixtureTool::class => [
                'scope' => ['enabled' => false, 'extra' => true],
            ],
        ],
    );
    expect($invalid['unreached'])->toBe([
        ClosedObjectFixtureTool::class => 'override-invalid:property-scope:additional-property:extra',
    ])->and(ClosedObjectFixtureTool::$authorizationReached)->toBeFalse();
});

it('reports contradictory emitted length and item bounds as unreached', function (): void {
    $array = McpDelegatedEnforcement::probe(ImpossibleBoundsFixtureServer::class);
    $string = McpDelegatedEnforcement::probe(ImpossibleStringBoundsFixtureServer::class);

    expect($array['invoked'])->toBe([])
        ->and($array['unreached'])->toBe([
            ImpossibleBoundsFixtureTool::class => 'property-items:empty-array-range',
        ])->and($string['invoked'])->toBe([])
        ->and($string['unreached'])->toBe([
            ImpossibleStringBoundsFixtureTool::class => 'property-code:empty-string-range',
        ]);
});

it('folds declaration offences into assertHonors', function (): void {
    expect(fn () => McpDelegatedEnforcement::assertHonors(
        DeclarationOffendingEnforcementFixtureServer::class,
        [DeclarationOffendingEnforcementFixtureTool::class],
    ))->toThrow(
        AssertionFailedError::class,
        DeclarationOffendingEnforcementFixtureTool::class.' is missing ToolClassification.',
    );
});

it('rejects an identity-blind tool even when it returns success', function (): void {
    $result = McpDelegatedEnforcement::probe(IdentityBlindSuccessFixtureServer::class);

    expect($result['errors'])->toBe([
        IdentityBlindSuccessFixtureTool::class => 'principal-not-observed',
    ])->and($result['violations'])->toContain(
        'tool-observation-failed:'.IdentityBlindSuccessFixtureTool::class.':principal-not-observed',
    );
});

it('makes role and delegated flag mismatches deciding observation failures', function (string $mode): void {
    ObservationMismatchFixtureTool::$mode = $mode;
    $result = McpDelegatedEnforcement::probe(ObservationMismatchFixtureServer::class);

    expect($result['principal_mismatches'])->toBe([
        ObservationMismatchFixtureTool::class => 'different-principal',
    ]);
})->with(['wrong role' => 'role', 'non-delegated observation' => 'delegated']);

it('makes a differing raw request principal a deciding mismatch', function (): void {
    $result = McpDelegatedEnforcement::probe(DifferentRawPrincipalFixtureServer::class);

    expect($result['principal_mismatches'])->toBe([
        DifferentRawPrincipalFixtureTool::class => 'different-request-principal',
    ]);
});

it('records every negative authorization failure path as failed', function (string $case): void {
    $negative = match ($case) {
        'throwing closure' => static function (): void {
            throw new RuntimeException('test-created negative case failure');
        },
        'zero invocations' => static function (): void {},
    };

    $result = McpDelegatedEnforcement::probe(
        CanonicalDelegatedFixtureServer::class,
        negativeAuthorization: $negative,
    );

    expect($result['negative_authorization'])->toBe('failed')
        ->and($result['violations'])->toContain($case === 'throwing closure'
            ? 'negative-authorization-failed:'.RuntimeException::class
            : 'negative-authorization-invoked-no-tool')
        ->and(fn () => McpDelegatedEnforcement::assertHonors(
            CanonicalDelegatedFixtureServer::class,
            [CanonicalDelegatedFixtureTool::class, ScopedDelegatedRowsFixtureTool::class],
            negativeAuthorization: $negative,
        ))->toThrow(AssertionFailedError::class);

    expect(DelegatedActor::query()->whereIn('identity_hash', [
        DelegatedActor::identityHash('https://bfc-enforcement.test', 'bfc-enforcement-primary'),
        DelegatedActor::identityHash('https://bfc-enforcement.test', 'bfc-enforcement-secondary'),
    ])->exists())->toBeFalse();
})->with(['throwing closure', 'zero invocations']);

it('records non-distinct negative subjects as a violation', function (): void {
    $actor = new DelegatedActor;
    $actor->forceFill(['id' => 902]);
    $principal = ActingPrincipal::delegatedRequest($actor, new DelegatedClaims(
        displayName: 'Same Subject',
        role: ConsoleRole::Member,
        onBehalfOf: null,
    ));
    $violations = [];
    $method = new ReflectionMethod(McpDelegatedEnforcement::class, 'negativeSubjectsAreDistinct');
    $arguments = [$principal, $principal, &$violations];

    expect($method->invokeArgs(null, $arguments))->toBeFalse()
        ->and($violations)->toBe(['negative-authorization-subjects-not-distinct']);
});

it('removes fixture-created key and actor rows after success and failure', function (): void {
    $reflection = new ReflectionClass(McpDelegatedAssertionFixture::class);
    $keyId = $reflection->getConstant('KEY_ID');
    $hashes = [
        DelegatedActor::identityHash('https://bfc-enforcement.test', 'bfc-enforcement-primary'),
        DelegatedActor::identityHash('https://bfc-enforcement.test', 'bfc-enforcement-secondary'),
    ];

    expect(McpDelegatedEnforcement::probe(CanonicalDelegatedFixtureServer::class)['violations'])->toBe([])
        ->and(ConsoleKey::query()->where('key_id', $keyId)->exists())->toBeFalse()
        ->and(DelegatedActor::query()->whereIn('identity_hash', $hashes)->exists())->toBeFalse();

    expect(McpDelegatedEnforcement::probe(CredentialOnlyDelegatedFixtureServer::class)['violations'])->not->toBe([])
        ->and(ConsoleKey::query()->where('key_id', $keyId)->exists())->toBeFalse()
        ->and(DelegatedActor::query()->whereIn('identity_hash', $hashes)->exists())->toBeFalse();
});

it('refuses a pre-existing fixture key without activating or changing it', function (): void {
    $reflection = new ReflectionClass(McpDelegatedAssertionFixture::class);
    $keyId = $reflection->getConstant('KEY_ID');
    $publicKey = $reflection->getConstant('PUBLIC_KEY');
    $key = app(ConsoleKeyring::class)->add($keyId, $publicKey);
    $key->refresh();
    $before = $key->getRawOriginal();

    $result = McpDelegatedEnforcement::probe(CanonicalDelegatedFixtureServer::class);
    $key->refresh();

    expect($result['violations'])->toContain('probe-setup-failed:fixture-state-collision:console-key-id')
        ->and($key->activated_at)->toBeNull()
        ->and($key->getRawOriginal())->toBe($before);
});

it('refuses a pre-existing fixture actor without overwriting its handoff state', function (): void {
    $assertion = consoleAssertionFor(
        issuer: 'https://bfc-enforcement.test',
        subject: 'bfc-enforcement-primary',
        displayName: 'Pre-existing Actor',
        role: ConsoleRole::Admin,
        onBehalfOf: 'Existing Agency',
    );
    $actor = DelegatedActor::recordHandoff($assertion);
    $actor->refresh();
    $before = $actor->getRawOriginal();

    $result = McpDelegatedEnforcement::probe(CanonicalDelegatedFixtureServer::class);
    $actor->refresh();

    expect($result['violations'])->toContain('probe-setup-failed:fixture-state-collision:delegated-actor-identity')
        ->and($actor->getRawOriginal())->toBe($before);
});
