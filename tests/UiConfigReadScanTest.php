<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageTransitions;
use ArtisanBuild\BuiltForCloud\Testing\UiConfigReadScan;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\UiConfigChainEnforcementPath;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\UiConfigEnforcementPath;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\UiConfigFacadeEnforcementPath;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\UiConfigRepositoryEnforcementPath;
use Illuminate\Contracts\Config\Repository;

/**
 * P5-AC13's installed-src enumeration. It covers all four statically
 * attributable literal read forms documented by UiConfigReadScan and no
 * dynamic config access; the executable rogue gates below are its controls.
 */
it('derives exactly the frozen visibility-only ui config consumer', function (): void {
    $root = dirname(__DIR__).'/src';
    $expected = [ManageTransitions::class.'|built-for-cloud.ui.managed_transitions|1'];

    expect(UiConfigReadScan::countPhpFiles($root))->toBeGreaterThan(0)
        ->and(UiConfigReadScan::discover($root))->toBe($expected);
});

it('reports an executed enforcement path for every supported ui config read form', function (): void {
    $gates = [
        'built-for-cloud.ui.rogue_chain_gate' => new UiConfigChainEnforcementPath,
        'built-for-cloud.ui.rogue_facade_gate' => new UiConfigFacadeEnforcementPath,
        'built-for-cloud.ui.rogue_gate' => new UiConfigEnforcementPath,
        'built-for-cloud.ui.rogue_repository_gate' => new UiConfigRepositoryEnforcementPath(app(Repository::class)),
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
    ]);
});
