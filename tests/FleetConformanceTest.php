<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\Jobs\DeliverOwnershipWebhook;
use ArtisanBuild\BuiltForCloud\Mcp\AdvertisesToolClassification;
use ArtisanBuild\BuiltForCloud\Testing\ConformanceFailed;
use ArtisanBuild\BuiltForCloud\Testing\ConsumerConformance;
use ArtisanBuild\BuiltForCloud\Testing\ContractAssertions;
use ArtisanBuild\BuiltForCloud\Testing\FleetConformance;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Queue;
use Laravel\Mcp\Server;
use Laravel\Mcp\Server\Tool;

uses(RefreshDatabase::class, ContractAssertions::class);

beforeEach(function (): void {
    Queue::fake();
});

final class AggregateOffendingMcpTool extends Tool
{
    use AdvertisesToolClassification;
}

final class AggregateOffendingMcpServer extends Server
{
    protected array $tools = [AggregateOffendingMcpTool::class];
}

/** @param list<string> $members
 * @return list<string>
 */
function sortedConformanceMembers(array $members): array
{
    sort($members);

    return $members;
}

/** @return array<string, list<string>> */
function packageConformanceExpected(): array
{
    return [
        'runtime.meta' => [],
        'runtime.auth_schema' => [],
        'runtime.credential_listing' => [],
        'runtime.transport_parity' => [],
        'thin_host' => [],
        'credential_paths' => sortedConformanceMembers([
            'path:Basic|ArtisanBuild\BuiltForCloud\Auth\BasicAuthenticator',
            'path:Bearer|ArtisanBuild\BuiltForCloud\Auth\BearerAuthenticator',
            'path:HMAC|Http\Middleware\VerifyHmacSignature+Hmac\HmacVerifier',
            'path:MCP|Http\Middleware\AuthenticateMcp:store-bearer+v4.public',
            'path:asymmetric|Actions\MintCredential::mintEnrollment',
            'path:enrollment|OnboardingToken+POST:/bfc/claim,/bfc/onboarding/issue,/exchange,/verify',
            'path:system|SubjectType::Operator/Application/Installation+AuditActorType::CliOperator',
        ]),
        'credential_writers' => sortedConformanceMembers([
            'ArtisanBuild\BuiltForCloud\Actions\MintCredential::mintEnrollment',
            'ArtisanBuild\BuiltForCloud\Actions\MintCredential::mintSecretBearing',
            'ArtisanBuild\BuiltForCloud\Actions\MintCredential::mintSigningKey',
            'ArtisanBuild\BuiltForCloud\Actions\RotateCredential::replaceWithEnrollment',
            'ArtisanBuild\BuiltForCloud\Actions\RotateCredential::replaceWithPendingSigningKey',
            'ArtisanBuild\BuiltForCloud\Actions\RotateCredential::replaceWithSecret',
            'ArtisanBuild\BuiltForCloud\OwnerCredentialMinter::mintFromHash',
            'ArtisanBuild\BuiltForCloud\UnifiedStoreCredentialMinter::mint',
        ]),
        'legacy_removal' => [],
        'system_authority' => sortedConformanceMembers([
            'ArtisanBuild\BuiltForCloud\Commands\ConsoleReKeyCommand',
            'ArtisanBuild\BuiltForCloud\Commands\ConsoleRetireKeyCommand',
            'ArtisanBuild\BuiltForCloud\Commands\CreateAdminCommand',
            'ArtisanBuild\BuiltForCloud\Commands\CredentialActivateCommand',
            'ArtisanBuild\BuiltForCloud\Commands\CredentialListCommand',
            'ArtisanBuild\BuiltForCloud\Commands\CredentialMintCommand',
            'ArtisanBuild\BuiltForCloud\Commands\CredentialRevokeCommand',
            'ArtisanBuild\BuiltForCloud\Commands\CredentialRotateCommand',
            'ArtisanBuild\BuiltForCloud\Commands\HmacRewrapCommand',
            'ArtisanBuild\BuiltForCloud\Commands\InstallOperatorCredentialCommand',
            'ArtisanBuild\BuiltForCloud\Commands\OutboxDrainCommand',
            'ArtisanBuild\BuiltForCloud\Commands\OwnershipMintClaimCommand',
            'ArtisanBuild\BuiltForCloud\Commands\OwnershipRemintOwnerTokenCommand',
            'ArtisanBuild\BuiltForCloud\Commands\SigningRootProvisionCommand',
            'ArtisanBuild\BuiltForCloud\Commands\SubjectOffboardCommand',
            'ArtisanBuild\BuiltForCloud\Commands\WarnExpiringCredentialsCommand',
            DeliverOwnershipWebhook::class,
        ]),
        'no_signing_path' => [],
        'ui_config_reads' => sortedConformanceMembers([
            'ArtisanBuild\BuiltForCloud\AppPurposeRegistry|built-for-cloud.credentials.app_purposes|1',
            'ArtisanBuild\BuiltForCloud\Http\Controllers\ManageTransitions|built-for-cloud.ui.managed_transitions|1',
            'ArtisanBuild\BuiltForCloud\LandingManifest|built-for-cloud.manifest|1',
            'ArtisanBuild\BuiltForCloud\LandingPageRegistrar|built-for-cloud.ui.landing_page|1',
            'ArtisanBuild\BuiltForCloud\UiCredentialPurposes|built-for-cloud.ui.credential_purposes|1',
        ]),
        'mcp_delegated' => [],
    ];
}

/**
 * @param  list<string>  $runtime
 * @param  list<string>  $capabilities
 * @param  array<string, list<string>>|null  $expected
 */
function packageConformanceSpec(
    array $runtime = ['auth_schema', 'credential_listing', 'meta', 'transport_parity'],
    array $capabilities = ['credentials', 'tokens'],
    ?array $expected = null,
): ConsumerConformance {
    $root = dirname(__DIR__);

    return new ConsumerConformance(
        consumer: 'package-fixture',
        consumerRoot: __DIR__.'/Fixtures/ThinHost',
        packageRoot: $root,
        sourceRoots: [__DIR__.'/Fixtures/ThinHost'],
        providerFiles: [$root.'/src/BuiltForCloudServiceProvider.php'],
        runtimeAssertions: $runtime,
        capabilities: $capabilities,
        purposeMappings: in_array('meta', $runtime, true) ? ['fixture.consume' => CredentialPurpose::Consumption] : [],
        mcpServer: null,
        expected: $expected ?? packageConformanceExpected(),
    );
}

/**
 * @param  list<string>|null  $providerFiles
 * @param  list<string>  $runtime
 * @param  list<string>  $capabilities
 * @param  class-string<Server>|null  $mcpServer
 */
function aggregateControlSpec(
    string $consumerRoot,
    ?array $providerFiles = null,
    array $runtime = [],
    array $capabilities = [],
    ?string $mcpServer = null,
): ConsumerConformance {
    $packageRoot = dirname(__DIR__);
    $providerFiles ??= [$packageRoot.'/src/BuiltForCloudServiceProvider.php'];
    sort($providerFiles);

    return new ConsumerConformance(
        consumer: 'aggregate-control',
        consumerRoot: $consumerRoot,
        packageRoot: $packageRoot,
        sourceRoots: [$consumerRoot],
        providerFiles: $providerFiles,
        runtimeAssertions: $runtime,
        capabilities: $capabilities,
        purposeMappings: [],
        mcpServer: $mcpServer,
        expected: packageConformanceExpected(),
    );
}

function aggregateControlRoot(string $relativePath, string $contents): string
{
    $root = sys_get_temp_dir().'/bfc-aggregate-control-'.bin2hex(random_bytes(6));
    $path = $root.'/'.$relativePath;
    mkdir(dirname($path), 0700, true);
    file_put_contents($path, $contents);

    return $root;
}

it('runs the single fleet entry point with every family and deterministic exact report schemas', function (): void {
    $spec = packageConformanceSpec();
    $first = (new FleetConformance($this))->inspect($spec);
    $second = $this->assertBuiltForCloudFleetConformance($spec);

    expect($first->passed)->toBeTrue()
        ->and($second->passed)->toBeTrue()
        ->and(array_keys($first->jsonSerialize()))->toBe([
            'schema_version', 'consumer', 'package_api_version', 'passed', 'families',
        ])
        ->and(array_keys($first->families))->toBe(ConsumerConformance::FAMILIES)
        ->and($second->canonicalJson())->toBe($first->canonicalJson());

    foreach ($first->families as $family) {
        expect(array_keys($family->jsonSerialize()))->toBe([
            'applicability', 'reason', 'visited', 'expected', 'discovered', 'violations', 'limits',
        ]);
    }

    expect($first->families['runtime.meta']->visited)->toBe(1)
        ->and($first->families['runtime.auth_schema']->visited)->toBe(1)
        ->and($first->families['runtime.credential_listing']->visited)->toBe(1)
        ->and($first->families['runtime.transport_parity']->visited)->toBe(1)
        ->and($first->families['thin_host']->visited)->toBeGreaterThan(0)
        ->and($first->families['mcp_delegated']->applicability)->toBe('not_applicable')
        ->and($first->families['mcp_delegated']->reason)->toBe('capability_not_declared');
});

it('returns the identical passing report and throws the identical failing report as canonical JSON only', function (): void {
    $expected = packageConformanceExpected();
    array_pop($expected['credential_paths']);
    $expected['credential_paths'][] = 'path:test-created-missing-member';
    sort($expected['credential_paths']);
    $spec = packageConformanceSpec(runtime: [], capabilities: [], expected: $expected);
    $fleet = new FleetConformance($this);
    $report = $fleet->inspect($spec);

    expect($report->passed)->toBeFalse()
        ->and($report->families['credential_paths']->violations)->toContain(
            'missing:path:test-created-missing-member',
            'unexpected:path:system|SubjectType::Operator/Application/Installation+AuditActorType::CliOperator',
        );

    try {
        $fleet->assert($spec);
    } catch (ConformanceFailed $failure) {
        expect($failure->report()->canonicalJson())->toBe($report->canonicalJson())
            ->and($failure->getMessage())->toBe($failure->report()->canonicalJson());

        return;
    }

    $this->fail('The independently mismatched expected inventory passed.');
});

it('accepts object members in any order while refusing missing unknown duplicate and incoherent declarations', function (): void {
    $input = [
        'consumer' => 'package-fixture',
        'consumer_root' => __DIR__.'/Fixtures/ThinHost',
        'package_root' => dirname(__DIR__),
        'source_roots' => [__DIR__.'/Fixtures/ThinHost'],
        'provider_files' => [dirname(__DIR__).'/src/BuiltForCloudServiceProvider.php'],
        'runtime_assertions' => [],
        'capabilities' => [],
        'purpose_mappings' => [],
        'mcp_server' => null,
        'expected' => packageConformanceExpected(),
    ];

    expect(fn () => ConsumerConformance::fromArray($input + ['unknown' => true]))
        ->toThrow(InvalidArgumentException::class);

    $reordered = array_reverse($input, true);
    $reordered['expected'] = array_reverse($reordered['expected'], true);
    $normalized = ConsumerConformance::fromArray($reordered);
    expect($normalized->capabilities)->toBe([])
        ->and(array_keys($normalized->expected))->toBe(ConsumerConformance::FAMILIES);

    $missing = $input;
    unset($missing['consumer']);
    expect(fn () => ConsumerConformance::fromArray($missing))->toThrow(InvalidArgumentException::class);

    $unknownFamily = $input;
    $unknownFamily['expected']['unknown'] = [];
    expect(fn () => ConsumerConformance::fromArray($unknownFamily))->toThrow(InvalidArgumentException::class);

    $escape = $input;
    $escape['source_roots'] = [dirname(__DIR__).'/src'];
    $escape['package_root'] = __DIR__.'/Fixtures/ThinHost';
    expect(fn () => ConsumerConformance::fromArray($escape))->toThrow(InvalidArgumentException::class, 'escapes');

    $mcp = $input;
    $mcp['runtime_assertions'] = ['meta'];
    $mcp['capabilities'] = ['mcp-delegated'];
    expect(fn () => ConsumerConformance::fromArray($mcp))->toThrow(InvalidArgumentException::class, 'requires');

    $withoutMeta = $input;
    $withoutMeta['capabilities'] = ['credentials'];
    expect(fn () => ConsumerConformance::fromArray($withoutMeta))->toThrow(InvalidArgumentException::class, 'runtime meta');

    $purposeWithoutMeta = $input;
    $purposeWithoutMeta['purpose_mappings'] = ['fixture.consume' => CredentialPurpose::Consumption];
    expect(fn () => ConsumerConformance::fromArray($purposeWithoutMeta))->toThrow(InvalidArgumentException::class, 'runtime meta');

    $duplicates = $input;
    $duplicates['source_roots'][] = __DIR__.'/Fixtures/ThinHost';
    expect(fn () => ConsumerConformance::fromArray($duplicates))->toThrow(InvalidArgumentException::class, 'sorted');
});

it('does not accept a declared capability without the live meta predicate', function (): void {
    $spec = packageConformanceSpec(
        runtime: ['meta'],
        capabilities: ['test-created-unobservable-capability'],
    );
    $report = (new FleetConformance($this))->inspect($spec);

    expect($report->passed)->toBeFalse()
        ->and($report->families['runtime.meta']->violations)->toBe(['assertion-failed:runtime.meta']);
});

it('rejects every scanner family positive control through the aggregate seam', function (): void {
    $legacySymbol = implode('', ['Api', 'Token']);
    $controls = [
        'thin_host' => [
            aggregateControlRoot('app/Models/User.php', "<?php\nfinal class AggregateUser {}\n"),
            'consumer/app/Models/User.php|app-user-model',
        ],
        'credential_paths' => [
            aggregateControlRoot('PurposeOmitted.php', <<<'PHP'
<?php
namespace AggregateControl;
use ArtisanBuild\BuiltForCloud\Auth\CredentialResolver;
use ArtisanBuild\BuiltForCloud\CredentialKind;
final class PurposeOmitted
{
    public function __construct(private CredentialResolver $resolver) {}
    public function authenticate(string $secret): mixed
    {
        return $this->resolver->resolve(CredentialKind::Bearer, $secret);
    }
}
PHP),
            'missing-purpose-rule:AggregateControl\\PurposeOmitted::authenticate',
        ],
        'credential_writers' => [
            aggregateControlRoot('RogueWriter.php', <<<'PHP'
<?php
namespace AggregateControl;
use ArtisanBuild\BuiltForCloud\Credential;
final class RogueWriter
{
    public function write(): Credential
    {
        return Credential::query()->create(['kind' => 'bearer']);
    }
}
PHP),
            'missing-purpose:AggregateControl\\RogueWriter::write',
        ],
        'legacy_removal' => [
            aggregateControlRoot('Legacy.php', "<?php\n{$legacySymbol}::query();\n"),
            'consumer/Legacy.php:2 [symbol:'.$legacySymbol.']',
        ],
        'no_signing_path' => [
            aggregateControlRoot('Signing.php', "<?php\nsodium_crypto_sign(\$message, \$key);\n"),
            'consumer/Signing.php|sodium_crypto_sign(',
        ],
        'ui_config_reads' => [
            aggregateControlRoot('RogueUiRead.php', "<?php\nnamespace AggregateControl;\nfinal class RogueUiRead { public function read(): mixed { return config('built-for-cloud.ui.rogue'); } }\n"),
            'published-configuration-dispositions',
        ],
    ];

    foreach ($controls as $family => [$root, $violation]) {
        $report = (new FleetConformance($this))->inspect(aggregateControlSpec($root));

        expect($report->passed)->toBeFalse($family)
            ->and($report->families[$family]->visited)->toBeGreaterThan(0, $family)
            ->and($report->families[$family]->violations)->toContain($violation);
    }

    $systemRoot = aggregateControlRoot('RogueSystem.php', <<<'PHP'
<?php
namespace AggregateControl;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Auth;
final class RogueSystemCommand extends Command
{
    public function handle(): int
    {
        Auth::login(User::query()->first());
        return self::SUCCESS;
    }
}
final class RogueSystemProvider
{
    public function boot(): void
    {
        $this->commands([RogueSystemCommand::class]);
    }
}
PHP);
    $systemReport = (new FleetConformance($this))->inspect(aggregateControlSpec(
        $systemRoot,
        [dirname(__DIR__).'/src/BuiltForCloudServiceProvider.php', $systemRoot.'/RogueSystem.php'],
    ));
    expect($systemReport->passed)->toBeFalse()
        ->and($systemReport->families['system_authority']->violations)
        ->toContain('human-principal:AggregateControl\\RogueSystemCommand');

    $mcpRoot = aggregateControlRoot('Clean.php', "<?php\nfinal class AggregateMcpConsumer {}\n");
    $mcpReport = (new FleetConformance($this))->inspect(aggregateControlSpec(
        $mcpRoot,
        runtime: ['meta'],
        capabilities: ['mcp-delegated'],
        mcpServer: AggregateOffendingMcpServer::class,
    ));
    expect($mcpReport->passed)->toBeFalse()
        ->and($mcpReport->families['mcp_delegated']->visited)->toBe(1)
        ->and($mcpReport->families['mcp_delegated']->violations)->toContain(
            AggregateOffendingMcpTool::class.' is missing IsReadOnly, IsDestructive, or IsIdempotent.',
            AggregateOffendingMcpTool::class.' is missing ToolClassification.',
            'mcp-delegated-conformance',
        );
});

it('never leaks absolute paths or test-created secret material in a failing report', function (): void {
    $secret = 'test-created-secret-'.bin2hex(random_bytes(8));
    $consumer = sys_get_temp_dir().'/bfc-conformance-'.bin2hex(random_bytes(6));
    mkdir($consumer);
    file_put_contents($consumer.'/Clean.php', "<?php\n\nfinal class CleanFixture { private string \$value = '".$secret."'; }\n");
    $expected = packageConformanceExpected();
    $expected['credential_paths'][] = 'path:test-created-missing-member';
    sort($expected['credential_paths']);
    $spec = new ConsumerConformance(
        consumer: 'anti-leak-fixture',
        consumerRoot: $consumer,
        packageRoot: dirname(__DIR__),
        sourceRoots: [$consumer],
        providerFiles: [dirname(__DIR__).'/src/BuiltForCloudServiceProvider.php'],
        runtimeAssertions: [],
        capabilities: [],
        purposeMappings: [],
        mcpServer: null,
        expected: $expected,
    );
    $json = (new FleetConformance($this))->inspect($spec)->canonicalJson();

    expect($json)->not->toContain(dirname(__DIR__))
        ->and($json)->not->toContain($consumer)
        ->and($json)->not->toContain($secret);
});
