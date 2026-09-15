<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AppPurposeRegistry;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageTransitions;
use ArtisanBuild\BuiltForCloud\Http\Controllers\UiHome;
use ArtisanBuild\BuiltForCloud\LandingManifest;
use ArtisanBuild\BuiltForCloud\LandingPageRegistrar;
use ArtisanBuild\BuiltForCloud\Testing\UiConfigReadScan;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\UiConfigChainEnforcementPath;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\UiConfigEnforcementPath;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\UiConfigFacadeEnforcementPath;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\UiConfigRepositoryEnforcementPath;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\UiConfigTypedGetterEnforcementPath;
use ArtisanBuild\BuiltForCloud\Tests\InventoryFixtures\PublishedConfigRogueRead;
use ArtisanBuild\BuiltForCloud\Tests\InventoryFixtures\UiConditionedHumanGate;
use ArtisanBuild\BuiltForCloud\Tests\InventoryFixtures\UiConditionedOwnershipAssertion;
use ArtisanBuild\BuiltForCloud\UiCredentialPurposes;
use Illuminate\Contracts\Config\Repository;

/**
 * P5-AC13's installed-src enumeration. It covers all four statically
 * attributable literal read forms and the typed-getter family documented by
 * UiConfigReadScan; the executable rogue gates below are its controls.
 */
it('derives exactly the named display and mount ui config consumers', function (): void {
    $root = dirname(__DIR__).'/src';
    $expected = [
        ManageTransitions::class.'|built-for-cloud.ui.managed_transitions|1' => 'managed-transition display',
        UiHome::class.'|built-for-cloud.ui.installation_credentials|1' => 'shell navigation display',
        UiHome::class.'|built-for-cloud.ui.managed_transitions|1' => 'shell navigation display',
        UiHome::class.'|built-for-cloud.ui.member_management|1' => 'shell navigation display',
        UiHome::class.'|built-for-cloud.ui.personal_credentials|1' => 'shell navigation display',
        UiHome::class.'|built-for-cloud.ui.session_management|1' => 'shell navigation display',
        LandingPageRegistrar::class.'|built-for-cloud.ui.landing_page|1' => 'optional public root mount',
        UiCredentialPurposes::class.'|built-for-cloud.ui.credential_purposes|1' => 'submitted app-purpose transport validator',
    ];

    expect(UiConfigReadScan::countPhpFiles($root))->toBeGreaterThan(0)
        ->and(UiConfigReadScan::discover($root))->toBe(array_keys($expected));
});

it('derives every published config read with a named disposition and detects rogue reads', function (): void {
    $expected = [
        AppPurposeRegistry::class.'|built-for-cloud.credentials.app_purposes|1' => 'mapper',
        ManageTransitions::class.'|built-for-cloud.ui.managed_transitions|1' => 'display',
        UiHome::class.'|built-for-cloud.ui.installation_credentials|1' => 'display',
        UiHome::class.'|built-for-cloud.ui.managed_transitions|1' => 'display',
        UiHome::class.'|built-for-cloud.ui.member_management|1' => 'display',
        UiHome::class.'|built-for-cloud.ui.personal_credentials|1' => 'display',
        UiHome::class.'|built-for-cloud.ui.session_management|1' => 'display',
        LandingManifest::class.'|built-for-cloud.manifest|1' => 'display',
        LandingPageRegistrar::class.'|built-for-cloud.ui.landing_page|1' => 'mount',
        UiCredentialPurposes::class.'|built-for-cloud.ui.credential_purposes|1' => 'transport-validator',
    ];

    expect(UiConfigReadScan::assertPublishedConfigurationDispositions(dirname(__DIR__).'/src'))->toBe($expected)
        ->and(fn () => UiConfigReadScan::assertPublishedConfigurationDispositions(
            dirname(__DIR__).'/src',
            [__DIR__.'/InventoryFixtures/PublishedConfigRogueRead.php'],
        ))->toThrow(RuntimeException::class, PublishedConfigRogueRead::class);
});

it('allows only views view-models the root mount and submitted-purpose validation to read ui config', function (): void {
    $expected = [
        ManageTransitions::class.'|built-for-cloud.ui.managed_transitions|1' => 'display',
        UiHome::class.'|built-for-cloud.ui.installation_credentials|1' => 'display',
        UiHome::class.'|built-for-cloud.ui.managed_transitions|1' => 'display',
        UiHome::class.'|built-for-cloud.ui.member_management|1' => 'display',
        UiHome::class.'|built-for-cloud.ui.personal_credentials|1' => 'display',
        UiHome::class.'|built-for-cloud.ui.session_management|1' => 'display',
        LandingPageRegistrar::class.'|built-for-cloud.ui.landing_page|1' => 'mount',
        UiCredentialPurposes::class.'|built-for-cloud.ui.credential_purposes|1' => 'transport-validator',
        'auth\\members.blade|built-for-cloud.ui.managed_transitions|1' => 'display',
    ];
    $roots = [dirname(__DIR__).'/resources/views'];

    expect(UiConfigReadScan::assertUiConfigurationDispositions(dirname(__DIR__).'/src', $roots))->toBe($expected);

    foreach ([
        UiConditionedHumanGate::class => __DIR__.'/InventoryFixtures/UiConditionedHumanGate.php',
        UiConditionedOwnershipAssertion::class => __DIR__.'/InventoryFixtures/UiConditionedOwnershipAssertion.php',
    ] as $class => $fixture) {
        expect(fn () => UiConfigReadScan::assertUiConfigurationDispositions(
            dirname(__DIR__).'/src',
            [...$roots, $fixture],
        ))->toThrow(RuntimeException::class, $class);
    }
});

it('reports an executed enforcement path for every supported ui config read form', function (): void {
    $gates = [
        'built-for-cloud.ui.rogue_chain_gate' => new UiConfigChainEnforcementPath,
        'built-for-cloud.ui.rogue_facade_gate' => new UiConfigFacadeEnforcementPath,
        'built-for-cloud.ui.rogue_gate' => new UiConfigEnforcementPath,
        'built-for-cloud.ui.rogue_repository_gate' => new UiConfigRepositoryEnforcementPath(app(Repository::class)),
        'built-for-cloud.ui.rogue_typed_gate' => new UiConfigTypedGetterEnforcementPath,
    ];

    foreach ($gates as $key => $gate) {
        config()->set($key, false);
        expect(fn () => $gate->enforce())->toThrow(RuntimeException::class);

        config()->set($key, true);
        $gate->enforce();
    }

    $fixtureReads = UiConfigReadScan::discover(__DIR__.'/Fixtures');

    expect($fixtureReads)->toBe([
        UiConfigChainEnforcementPath::class.'|built-for-cloud.ui.rogue_chain_gate|1',
        UiConfigEnforcementPath::class.'|built-for-cloud.ui.rogue_gate|1',
        UiConfigFacadeEnforcementPath::class.'|built-for-cloud.ui.rogue_facade_gate|1',
        UiConfigRepositoryEnforcementPath::class.'|built-for-cloud.ui.rogue_repository_gate|1',
        UiConfigTypedGetterEnforcementPath::class.'|built-for-cloud.ui.rogue_typed_gate|1',
    ]);
});
