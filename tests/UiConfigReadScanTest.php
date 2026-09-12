<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageTransitions;
use ArtisanBuild\BuiltForCloud\Testing\UiConfigReadScan;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\UiConfigEnforcementPath;

/**
 * P5-AC13's installed-src enumeration. It covers the direct literal config
 * reads documented by UiConfigReadScan and no dynamic or indirect config
 * access; the executable rogue gate below is its positive control.
 */
it('derives exactly the frozen visibility-only ui config consumer', function (): void {
    $root = dirname(__DIR__).'/src';
    $expected = [ManageTransitions::class.'|built-for-cloud.ui.managed_transitions|1'];

    expect(UiConfigReadScan::countPhpFiles($root))->toBeGreaterThan(0)
        ->and(UiConfigReadScan::discover($root))->toBe($expected);
});

it('reports a genuine enforcement path that branches on a ui config key', function (): void {
    $gate = new UiConfigEnforcementPath;
    config()->set('built-for-cloud.ui.rogue_gate', false);

    expect(fn () => $gate->enforce())->toThrow(RuntimeException::class);

    config()->set('built-for-cloud.ui.rogue_gate', true);
    $gate->enforce();

    $fixtureReads = UiConfigReadScan::discover(__DIR__.'/Fixtures');

    expect($fixtureReads)->toBe([
        UiConfigEnforcementPath::class.'|built-for-cloud.ui.rogue_gate|1',
    ]);
});
