<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Http\Controllers\ClientObservations;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\Testing\LegacyRemovalInventory;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;

uses(RefreshDatabase::class);

function removalPackageRoot(): string
{
    return dirname(__DIR__);
}

/** @return list<string> */
function transitionCommandSignatures(): array
{
    return [
        implode(':', ['token', 'create']),
        implode(':', ['token', 'list']),
        implode(':', ['token', 'revoke']),
        implode(':', ['token', 'rotate']),
        implode(':', ['token', 'usage']),
        implode(':', ['bfc', 'token', 'revoke-self']),
        implode(':', ['fallback-token', 'generate']),
    ];
}

/** @return array<string, 'migrate'|'delete'|'keep-as-historical'> */
function frozenTestRemovalDispositions(): array
{
    $delete = [
        'tests/ClaimCodeBurnTest.php',
        'tests/CredentialApiTest.php',
        'tests/LegacyRotationTest.php',
        'tests/MetadataShapeLegacyApiTest.php',
        'tests/P5bCarryForwardProcessTest.php',
        'tests/P5bCarryForwardTest.php',
        'tests/TokenCommandsTest.php',
        'tests/TokenCoreTest.php',
        'tests/TokenRevokeSelfTest.php',
        'tests/Fixtures/p5b-carry-forward-worker.php',
    ];
    $migrate = [
        'tests/AppActionAuditTest.php',
        'tests/AuditStreamTest.php',
        'tests/AuthenticateMcpTest.php',
        'tests/ClaimExchangeSeamTest.php',
        'tests/ClaimSurfaceTest.php',
        'tests/ClientIdentityObservationTest.php',
        'tests/ClientIdentityTest.php',
        'tests/CloudCommandRunnerTest.php',
        'tests/ConsoleKeyCustodyTest.php',
        'tests/ConsoleKeyRetirementTest.php',
        'tests/ConsoleVitalsTest.php',
        'tests/ContractAssertionsTest.php',
        'tests/CredentialDeliveryBoundaryTest.php',
        'tests/CredentialGuardTest.php',
        'tests/CredentialPathInventoryTest.php',
        'tests/ExpiryWarningTest.php',
        'tests/Fixtures/SecondStoreResolver.php',
        'tests/Fixtures/UnifiedStoreDeclaration.php',
        'tests/Fixtures/operator-route-cache.php',
        'tests/Fixtures/personal-hmac-process.php',
        'tests/Fixtures/unified-claim-process.php',
        'tests/HeadlessThrottleTest.php',
        'tests/HmacActivationTest.php',
        'tests/HmacDeliveryTest.php',
        'tests/HmacRewrapTest.php',
        'tests/HmacRotationTest.php',
        'tests/HttpContractDocTest.php',
        'tests/InitialOwnershipClaimMintTest.php',
        'tests/InstallScaffoldTest.php',
        'tests/InstallerMintTest.php',
        'tests/LifecycleNotificationTest.php',
        'tests/LocalCommandsTest.php',
        'tests/ManagedIngressManifestTest.php',
        'tests/ManagedNoLocalBypassTest.php',
        'tests/McpToolGateTest.php',
        'tests/MetadataShapeTest.php',
        'tests/OffboardingTest.php',
        'tests/OnboardingEndpointsTest.php',
        'tests/OperatorRouteInventoryTest.php',
        'tests/OutboxTest.php',
        'tests/OwnershipCommandsTest.php',
        'tests/OwnershipEndpointsTest.php',
        'tests/OwnershipFoundationTest.php',
        'tests/PackageRouteMiddlewareCollisionTest.php',
        'tests/PersonalCredentialsTest.php',
        'tests/Pest.php',
        'tests/RotationTest.php',
        'tests/ServiceProviderTest.php',
        'tests/SubjectsAuthorityTest.php',
        'tests/Support/StandaloneSurfaceInventory.php',
        'tests/SurfaceSelectionTest.php',
        'tests/TwoTransportVerbsTest.php',
    ];

    return [
        ...array_fill_keys($delete, 'delete'),
        ...array_fill_keys($migrate, 'migrate'),
    ];
}

it('reports all six forbidden executable-symbol control kinds at their file and line', function (): void {
    $root = removalControlTree();
    $apiToken = implode('', ['Api', 'Token']);
    $adminToken = implode('', ['Admin', 'Token']);
    $ownerTokenId = implode('_', ['owner', 'token', 'id']);
    $durableTokenId = implode('_', ['durable', 'token', 'id']);
    $fallbackKey = implode('_', ['fallback', 'token']);
    $fallbackEnv = implode('_', ['FALLBACK', 'TOKEN']);

    file_put_contents($root.'/src/ForbiddenSymbols.php', "<?php\nuse Vendor\\{$apiToken};\nAuditActorType::{$adminToken};\n\$row->{$ownerTokenId};\n\$row->update(['{$durableTokenId}' => 'id']);\nconfig('built-for-cloud.{$fallbackKey}');\nenv('{$fallbackEnv}');\n");

    $offences = LegacyRemovalInventory::productionOffences($root);

    expect($offences)->toContain(
        'src/ForbiddenSymbols.php:2 [symbol:'.$apiToken.']',
        'src/ForbiddenSymbols.php:3 [enum:AuditActorType::'.$adminToken.']',
        'src/ForbiddenSymbols.php:4 [identifier:'.$ownerTokenId.']',
        'src/ForbiddenSymbols.php:5 [identifier:'.$durableTokenId.']',
        'src/ForbiddenSymbols.php:6 [config:built-for-cloud.'.$fallbackKey.']',
        'src/ForbiddenSymbols.php:7 [env:'.$fallbackEnv.']',
    );
});

it('reports legacy migration config route and public-document controls at their file and line', function (): void {
    $root = removalControlTree();
    $table = implode('_', ['api', 'tokens']);
    $configKey = implode('_', ['credential', 'api']);
    $fallbackKey = implode('_', ['fallback', 'token']);

    file_put_contents($root.'/database/migrations/legacy.php', "<?php\nSchema::create('{$table}', fn (\$table) => null);\n");
    file_put_contents($root.'/config/built-for-cloud.php', "<?php\nreturn ['{$fallbackKey}' => null, '{$configKey}' => ['prefix' => 'api/credentials']];\n");
    file_put_contents($root.'/src/LegacyRoute.php', "<?php\nconfig('built-for-cloud.{$configKey}.prefix');\n\$router->get('/client-observations', ClientObservations::class);\n");
    file_put_contents($root.'/README.md', "Current installs use {$table}.\n");

    expect(LegacyRemovalInventory::productionOffences($root))->toContain(
        'database/migrations/legacy.php:2 [schema:'.$table.']',
        'config/built-for-cloud.php:2 [config:built-for-cloud.'.$fallbackKey.']',
        'config/built-for-cloud.php:2 [config:built-for-cloud.'.$configKey.']',
        'src/LegacyRoute.php:2 [config:built-for-cloud.'.$configKey.']',
    )->and(LegacyRemovalInventory::publicDocumentOffences($root))->toContain(
        'README.md:1 [legacy-store]',
    );
});

it('reports a test-corpus marker control at its file and line', function (): void {
    $root = removalControlTree();
    $symbol = implode('', ['Api', 'Token']);
    file_put_contents($root.'/tests/InjectedLegacyTest.php', "<?php\n{$symbol}::factory();\n");

    expect(LegacyRemovalInventory::testFilesWithRemovalMarkers($root))->toHaveKey('tests/InjectedLegacyTest.php')
        ->and(LegacyRemovalInventory::testFilesWithRemovalMarkers($root)['tests/InjectedLegacyTest.php'])
        ->toContain($symbol.'@2');
});

it('enforces the frozen disposition of every test file carrying a removal marker', function (): void {
    $markers = LegacyRemovalInventory::testFilesWithRemovalMarkers(removalPackageRoot());
    $dispositions = frozenTestRemovalDispositions();

    expect(array_values(array_diff(array_keys($markers), array_keys($dispositions))))->toBe([]);

    foreach ($dispositions as $file => $disposition) {
        if ($disposition === 'delete') {
            expect($file)->not->toBeFile();

            continue;
        }

        if ($disposition === 'migrate') {
            expect($markers)->not->toHaveKey($file);

            continue;
        }

        expect($markers)->toHaveKey($file);
    }
});

it('finds no forbidden production or public-document remnants in the installed tree', function (): void {
    expect(LegacyRemovalInventory::productionOffences(removalPackageRoot()))->toBe([])
        ->and(LegacyRemovalInventory::publicDocumentOffences(removalPackageRoot()))->toBe([]);
});

it('pins the fresh schema config commands and client-observation route identity', function (): void {
    $config = config('built-for-cloud');
    $commands = array_keys(Artisan::all());
    $clientObservationRoutes = collect(Route::getRoutes()->getRoutes())
        ->filter(static fn ($route): bool => $route->getActionName() === ClientObservations::class)
        ->values();

    expect(Schema::hasTable(implode('_', ['api', 'tokens'])))->toBeFalse()
        ->and(Schema::hasColumn('ownership', implode('_', ['owner', 'token', 'id'])))->toBeFalse()
        ->and(Schema::hasColumn('ownership', 'owner_credential_id'))->toBeTrue()
        ->and(Schema::hasColumn('onboarding_tokens', implode('_', ['durable', 'token', 'id'])))->toBeFalse()
        ->and(Schema::hasColumn('onboarding_tokens', 'durable_credential_id'))->toBeTrue()
        ->and(Schema::hasColumn('onboarding_tokens', implode('_', ['durable', 'store'])))->toBeFalse()
        ->and(Arr::has($config, implode('_', ['fallback', 'token'])))->toBeFalse()
        ->and(Arr::has($config, implode('_', ['credential', 'api'])))->toBeFalse()
        ->and(array_values(array_intersect($commands, transitionCommandSignatures())))->toBe([])
        ->and($clientObservationRoutes)->toHaveCount(1)
        ->and($clientObservationRoutes->first()?->methods())->toContain('GET')
        ->and($clientObservationRoutes->first()?->uri())->toBe('bfc/client-observations')
        ->and($clientObservationRoutes->first()?->gatherMiddleware())->toContain(
            EnsureCredentialAdmin::class.':'.OperatorAbility::CredentialRead->value,
        );
});

it('reports an injected old client-observation alias and configurable key', function (): void {
    $key = implode('_', ['credential', 'api']);
    config(["built-for-cloud.{$key}" => ['prefix' => 'api/credentials']]);
    Route::get('/api/credentials/client-observations', ClientObservations::class);

    $aliases = collect(Route::getRoutes()->getRoutes())
        ->filter(static fn ($route): bool => $route->getActionName() === ClientObservations::class)
        ->map(static fn ($route): string => implode('|', $route->methods()).' '.$route->uri())
        ->values()
        ->all();

    expect(Arr::has(config('built-for-cloud'), $key))->toBeTrue()
        ->and($aliases)->toContain('GET|HEAD api/credentials/client-observations')
        ->and($aliases)->toHaveCount(2);
});

function removalControlTree(): string
{
    $root = sys_get_temp_dir().'/bfc-removal-control-'.bin2hex(random_bytes(8));

    mkdir($root.'/src', 0777, true);
    mkdir($root.'/database/migrations', 0777, true);
    mkdir($root.'/config', 0777, true);
    mkdir($root.'/docs', 0777, true);
    mkdir($root.'/tests', 0777, true);
    file_put_contents($root.'/composer.json', '{}');
    file_put_contents($root.'/src/BuiltForCloudServiceProvider.php', "<?php\n");
    file_put_contents($root.'/config/built-for-cloud.php', "<?php\nreturn [];\n");
    file_put_contents($root.'/README.md', "Unified credentials.\n");
    file_put_contents($root.'/docs/http-contract.md', "Unified credentials.\n");

    return $root;
}
