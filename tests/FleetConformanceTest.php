<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\Jobs\DeliverOwnershipWebhook;
use ArtisanBuild\BuiltForCloud\Testing\ConformanceFailed;
use ArtisanBuild\BuiltForCloud\Testing\ConsumerConformance;
use ArtisanBuild\BuiltForCloud\Testing\ContractAssertions;
use ArtisanBuild\BuiltForCloud\Testing\FleetConformance;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Queue;

uses(RefreshDatabase::class, ContractAssertions::class);

beforeEach(function (): void {
    Queue::fake();
});

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
 * @param list<string> $runtime
 * @param list<string> $capabilities
 * @param array<string, list<string>>|null $expected
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
        requiredCapabilities: $capabilities,
        purposeMappings: ['fixture.consume' => CredentialPurpose::Consumption],
        mcpServer: null,
        expected: $expected ?? packageConformanceExpected(),
    );
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
    $spec = packageConformanceSpec(runtime: [], expected: $expected);
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

it('refuses roots fields families ordering duplicates and mcp declarations that violate version one', function (): void {
    $input = [
        'consumer' => 'package-fixture',
        'consumer_root' => __DIR__.'/Fixtures/ThinHost',
        'package_root' => dirname(__DIR__),
        'source_roots' => [__DIR__.'/Fixtures/ThinHost'],
        'provider_files' => [dirname(__DIR__).'/src/BuiltForCloudServiceProvider.php'],
        'runtime_assertions' => [],
        'required_capabilities' => [],
        'purpose_mappings' => [],
        'mcp_server' => null,
        'expected' => packageConformanceExpected(),
    ];

    expect(fn () => ConsumerConformance::fromArray($input + ['unknown' => true]))
        ->toThrow(InvalidArgumentException::class);

    $unknownFamily = $input;
    $unknownFamily['expected']['unknown'] = [];
    expect(fn () => ConsumerConformance::fromArray($unknownFamily))->toThrow(InvalidArgumentException::class);

    $escape = $input;
    $escape['source_roots'] = [dirname(__DIR__).'/src'];
    $escape['package_root'] = __DIR__.'/Fixtures/ThinHost';
    expect(fn () => ConsumerConformance::fromArray($escape))->toThrow(InvalidArgumentException::class, 'escapes');

    $mcp = $input;
    $mcp['required_capabilities'] = ['mcp-delegated'];
    expect(fn () => ConsumerConformance::fromArray($mcp))->toThrow(InvalidArgumentException::class, 'requires');

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
        requiredCapabilities: [],
        purposeMappings: [],
        mcpServer: null,
        expected: $expected,
    );
    $json = (new FleetConformance($this))->inspect($spec)->canonicalJson();

    expect($json)->not->toContain(dirname(__DIR__))
        ->and($json)->not->toContain($consumer)
        ->and($json)->not->toContain($secret);
});
