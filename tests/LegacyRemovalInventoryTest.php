<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Http\Controllers\ClientObservations;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\Testing\LegacyRemovalInventory;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Symfony\Component\Process\Process as SymfonyProcess;

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
        'tests/CredentialApiTest.php',
        'tests/LegacyRotationTest.php',
        'tests/MetadataShapeLegacyApiTest.php',
        'tests/TokenCommandsTest.php',
        'tests/TokenCoreTest.php',
        'tests/TokenRevokeSelfTest.php',
    ];
    $migrate = [
        'tests/AppActionAuditTest.php',
        'tests/AuditStreamTest.php',
        'tests/AuthenticateMcpTest.php',
        'tests/ClaimExchangeSeamTest.php',
        'tests/ClaimCodeBurnTest.php',
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
        'tests/ExpiryWarningTest.php',
        'tests/Fixtures/UnifiedStoreDeclaration.php',
        'tests/Fixtures/operator-route-cache.php',
        'tests/Fixtures/personal-hmac-process.php',
        'tests/Fixtures/p5b-carry-forward-worker.php',
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
        'tests/ManagedTransitionCommitTest.php',
        'tests/ManagedTransitionTest.php',
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
        'tests/P5bCarryForwardProcessTest.php',
        'tests/P5bCarryForwardTest.php',
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
        'tests/CredentialPathInventoryTest.php' => 'keep-as-historical',
    ];
}

/** @return array<string, string> */
function baselineDeletedTestContents(): array
{
    $contents = [];

    foreach (frozenTestRemovalDispositions() as $file => $disposition) {
        if ($disposition !== 'delete') {
            continue;
        }

        $process = new SymfonyProcess(['git', 'show', '96a4eab:'.$file], removalPackageRoot());
        $process->mustRun();
        $contents[$file] = $process->getOutput();
    }

    return $contents;
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

it('allows only the surviving audit actor case while reporting another symbol with the same short name', function (): void {
    $root = removalControlTree();
    $apiToken = implode('', ['Api', 'Token']);
    $auditType = implode('\\', ['ArtisanBuild', 'BuiltForCloud', 'Audit', 'AppActorType']);

    file_put_contents($root.'/src/AuditCases.php', "<?php\n\\{$auditType}::{$apiToken};\n\\Vendor\\{$apiToken}::query();\n");
    file_put_contents($root.'/src/ImportedAuditCase.php', "<?php\nuse {$auditType};\nAppActorType::{$apiToken};\n");
    file_put_contents($root.'/src/AliasedAuditCase.php', "<?php\nuse {$auditType} as Actor;\nActor::{$apiToken};\n");

    expect(LegacyRemovalInventory::productionOffences($root))
        ->not->toContain('src/AuditCases.php:2 [symbol:'.$apiToken.']')
        ->not->toContain('src/ImportedAuditCase.php:3 [symbol:'.$apiToken.']')
        ->not->toContain('src/AliasedAuditCase.php:3 [symbol:'.$apiToken.']')
        ->toContain('src/AuditCases.php:3 [symbol:'.$apiToken.']');
});

it('reports an aliased forbidden enum case at its file and line', function (): void {
    $root = removalControlTree();
    $auditType = implode('', ['Audit', 'Actor', 'Type']);
    $adminToken = implode('', ['Admin', 'Token']);

    file_put_contents($root.'/src/AliasedEnum.php', "<?php\nuse ArtisanBuild\\BuiltForCloud\\{$auditType} as Actor;\nActor::{$adminToken};\n");

    expect(LegacyRemovalInventory::productionOffences($root))
        ->toContain('src/AliasedEnum.php:3 [enum:'.$auditType.'::'.$adminToken.']');
});

it('reports forbidden string enum lookups at their file and line', function (): void {
    $root = removalControlTree();
    $auditType = implode('', ['Audit', 'Actor', 'Type']);
    $appActorType = implode('', ['App', 'Actor', 'Type']);
    $adminValue = implode('_', ['admin', 'token']);
    $legacyValue = implode('_', ['legacy', 'api', 'token']);
    $adminToken = implode('', ['Admin', 'Token']);
    $legacyCase = implode('', ['Legacy', 'Api', 'Token']);

    file_put_contents($root.'/src/StringEnums.php', "<?php\n{$auditType}::from('{$adminValue}');\n{$appActorType}::tryFrom('{$legacyValue}');\n");

    expect(LegacyRemovalInventory::productionOffences($root))->toContain(
        'src/StringEnums.php:2 [enum:'.$auditType.'::'.$adminToken.']',
        'src/StringEnums.php:3 [enum:Audit\\'.$appActorType.'::'.$legacyCase.']',
    );
});

it('reports forbidden string class names at their file and line', function (): void {
    $root = removalControlTree();
    $registry = implode('', ['Token', 'Registry']);
    $minter = implode('', ['Api', 'Token', 'Minter']);
    $registryClass = implode('\\', ['ArtisanBuild', 'BuiltForCloud', $registry]);
    $minterClass = implode('\\', ['ArtisanBuild', 'BuiltForCloud', $minter]);

    file_put_contents($root.'/src/StringClasses.php', "<?php\napp('{$registryClass}');\n\$class = '{$minterClass}';\n");

    expect(LegacyRemovalInventory::productionOffences($root))->toContain(
        'src/StringClasses.php:2 [symbol:'.$registry.']',
        'src/StringClasses.php:3 [symbol:'.$minter.']',
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
        'README.md:1 [table:'.$table.']',
    );
});

it('derives document markers for every removed inventory form at file and line', function (): void {
    $root = removalControlTree();
    $class = implode('', ['Ensure', 'Admin', 'Token']);
    $alias = implode('.', ['bfc', 'token', 'admin']);
    $column = implode('_', ['owner', 'token', 'id']);
    $config = implode('_', ['fallback', 'token']);
    $command = implode(':', ['token', 'create']);

    file_put_contents($root.'/README.md', implode("\n", [
        "Removed class {$class}.",
        "Removed alias {$alias}.",
        "Removed column {$column}.",
        "Removed config {$config}.",
        "Removed command {$command}.",
    ])."\n");

    expect(LegacyRemovalInventory::publicDocumentOffences($root))->toContain(
        'README.md:1 [class:'.$class.']',
        'README.md:2 [alias:'.$alias.']',
        'README.md:3 [column:'.$column.']',
        'README.md:4 [config:'.$config.']',
        'README.md:5 [command-token-create]',
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

it('reports a bare legacy table-name test control at its file and line', function (): void {
    $root = removalControlTree();
    $table = implode('_', ['api', 'tokens']);
    file_put_contents($root.'/tests/InjectedLegacyTableTest.php', "<?php\nDB::table('{$table}')->count();\n");

    $markers = LegacyRemovalInventory::testFilesWithRemovalMarkers($root);

    expect($markers)->toHaveKey('tests/InjectedLegacyTableTest.php')
        ->and($markers['tests/InjectedLegacyTableTest.php'])
        ->toContain($table.'@2');
});

it('enforces the frozen disposition of every test file carrying a removal marker', function (): void {
    expect(LegacyRemovalInventory::testRemovalDispositionOffences(
        removalPackageRoot(),
        frozenTestRemovalDispositions(),
        baselineDeletedTestContents(),
    ))->toBe([]);
});

it('refuses a delete file that solely covers a surviving class-like symbol', function (): void {
    $root = removalControlTree();
    $symbol = implode('', ['Surviving', 'Primitive']);

    file_put_contents($root.'/src/'.$symbol.'.php', "<?php\nfinal class {$symbol} {}\n");

    expect(LegacyRemovalInventory::testRemovalDispositionOffences(
        $root,
        ['tests/InjectedMixedTest.php' => 'delete'],
        ['tests/InjectedMixedTest.php' => "<?php\n{$symbol}::exercise();\n"],
    ))->toContain('tests/InjectedMixedTest.php:delete-mixed-symbol='.$symbol);
});

it('finds no forbidden production remnants in the installed tree', function (): void {
    expect(LegacyRemovalInventory::productionOffences(removalPackageRoot()))->toBe([]);
});

it('finds no removed surfaces in installed public documents', function (): void {
    expect(LegacyRemovalInventory::publicDocumentOffences(removalPackageRoot()))->toBe([]);
});

it('pins the fresh schema config commands and client-observation route identity', function (): void {
    $config = config('built-for-cloud');
    $commands = array_keys(Artisan::all());
    $legacyController = 'ArtisanBuild\\BuiltForCloud\\Http\\Controllers\\'.implode('', ['Manage', 'Tokens']);
    $legacyRoutes = collect(Route::getRoutes()->getRoutes())
        ->filter(static fn ($route): bool => str_starts_with($route->getActionName(), $legacyController.'@'))
        ->values();
    $clientObservationRoutes = collect(Route::getRoutes()->getRoutes())
        ->filter(static fn ($route): bool => $route->getActionName() === ClientObservations::class)
        ->values();
    $ownershipTargets = collect(DB::select("PRAGMA foreign_key_list('ownership')"))
        ->map(static fn (object $key): string => "{$key->from}:{$key->table}.{$key->to}:{$key->on_delete}")
        ->filter(static fn (string $target): bool => str_starts_with($target, 'owner_'))
        ->values()
        ->all();
    $onboardingTargets = collect(DB::select("PRAGMA foreign_key_list('onboarding_tokens')"))
        ->map(static fn (object $key): string => "{$key->from}:{$key->table}.{$key->to}:{$key->on_delete}")
        ->filter(static fn (string $target): bool => str_starts_with($target, 'durable_'))
        ->values()
        ->all();
    $violations = [];

    if (Schema::hasTable(implode('_', ['api', 'tokens']))) {
        $violations[] = 'schema:legacy-table-present';
    }
    foreach ([
        ['ownership', implode('_', ['owner', 'token', 'id'])],
        ['onboarding_tokens', implode('_', ['durable', 'token', 'id'])],
        ['onboarding_tokens', implode('_', ['durable', 'store'])],
    ] as [$table, $column]) {
        if (Schema::hasColumn($table, $column)) {
            $violations[] = "schema:legacy-column-present:{$table}.{$column}";
        }
    }
    if (! Schema::hasColumn('ownership', 'owner_credential_id')) {
        $violations[] = 'schema:missing:ownership.owner_credential_id';
    }
    if (! Schema::hasColumn('onboarding_tokens', 'durable_credential_id')) {
        $violations[] = 'schema:missing:onboarding_tokens.durable_credential_id';
    }
    if ($ownershipTargets !== ['owner_credential_id:credentials.id:SET NULL']) {
        $violations[] = 'schema:ownership-targets='.implode(',', $ownershipTargets);
    }
    if ($onboardingTargets !== ['durable_credential_id:credentials.id:SET NULL']) {
        $violations[] = 'schema:onboarding-targets='.implode(',', $onboardingTargets);
    }
    foreach ([implode('_', ['fallback', 'token']), implode('_', ['credential', 'api'])] as $key) {
        if (Arr::has($config, $key)) {
            $violations[] = 'config:key-present:'.$key;
        }
    }
    foreach (array_values(array_intersect($commands, transitionCommandSignatures())) as $command) {
        $violations[] = 'command:registered:'.$command;
    }
    foreach ($legacyRoutes as $route) {
        $violations[] = 'route:legacy-action:'.implode('|', $route->methods()).' '.$route->uri();
    }
    if ($clientObservationRoutes->count() !== 1) {
        $violations[] = 'route:client-observations-count='.$clientObservationRoutes->count();
    } else {
        $route = $clientObservationRoutes->first();
        if (! in_array('GET', $route->methods(), true)) {
            $violations[] = 'route:client-observations-methods='.implode('|', $route->methods());
        }
        if ($route->uri() !== 'bfc/client-observations') {
            $violations[] = 'route:client-observations-uri='.$route->uri();
        }
        $gate = EnsureCredentialAdmin::class.':'.OperatorAbility::CredentialRead->value;
        if (! in_array($gate, $route->gatherMiddleware(), true)) {
            $violations[] = 'route:client-observations-gate-missing='.$gate;
        }
    }

    sort($violations);

    expect($violations)->toBe([]);
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
