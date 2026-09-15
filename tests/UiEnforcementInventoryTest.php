<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureManagedAuthority;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureStandaloneAuthority;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUiAuthority;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAdmin;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAuthenticated;
use ArtisanBuild\BuiltForCloud\ManagedAccountAccess;
use ArtisanBuild\BuiltForCloud\ManagedFreshness;
use ArtisanBuild\BuiltForCloud\StandaloneRouteOwnership;
use ArtisanBuild\BuiltForCloud\Testing\UiEnforcementInventory;
use ArtisanBuild\BuiltForCloud\Tests\InventoryFixtures\UiConditionedHumanGate;

function p5fEnforcementDisposition(): array
{
    return [
        EnsureManagedAuthority::class.'::handle' => ['managed login in standalone mode'],
        EnsureStandaloneAuthority::class.'::handle' => ['standalone route in managed mode'],
        EnsureUiAuthority::class.'::handle' => ['invalid installation authority'],
        EnsureUserIsAdmin::class.'::handle' => [
            'unauthenticated', 'inactive', 'unknown-role', 'delegated human',
            'removed managed human', 'disabled managed human', 'stale managed human',
        ],
        EnsureUserIsAuthenticated::class.'::handle' => [
            'unauthenticated',
            'UI standalone unauthenticated -> bfc.login with relative intended',
            'UI managed unauthenticated -> bfc.managed.login with relative intended',
            'UI invalid authority unauthenticated -> 404',
            'inactive', 'unknown-role', 'delegated human',
            'removed managed human', 'disabled managed human', 'stale managed human',
        ],
        ManagedAccountAccess::class.'::allows' => [
            'removed managed human', 'disabled managed human', 'stale managed human',
        ],
        ManagedFreshness::class.'::allows' => [
            'removed managed human', 'disabled managed human', 'stale managed human',
        ],
        StandaloneRouteOwnership::class.'::assertMatched' => ['required standalone middleware missing at match'],
        StandaloneRouteOwnership::class.'::assertOwned' => ['required standalone middleware missing at boot'],
        StandaloneRouteOwnership::class.'::assertPackageMiddlewareMatched' => ['required package middleware missing at match'],
        StandaloneRouteOwnership::class.'::assertPackageMiddlewareOwned' => ['required package middleware missing at boot'],
    ];
}

it('pins the exact eleven direct enforcement members dispositions and candidate-head locations', function (): void {
    $expected = [
        ['member' => EnsureManagedAuthority::class.'::handle', 'path' => 'src/Http/Middleware/EnsureManagedAuthority.php', 'line' => 16, 'kind' => 'human-or-mode-gate'],
        ['member' => EnsureStandaloneAuthority::class.'::handle', 'path' => 'src/Http/Middleware/EnsureStandaloneAuthority.php', 'line' => 16, 'kind' => 'human-or-mode-gate'],
        ['member' => EnsureUiAuthority::class.'::handle', 'path' => 'src/Http/Middleware/EnsureUiAuthority.php', 'line' => 15, 'kind' => 'human-or-mode-gate'],
        ['member' => EnsureUserIsAdmin::class.'::handle', 'path' => 'src/Http/Middleware/EnsureUserIsAdmin.php', 'line' => 72, 'kind' => 'human-or-mode-gate'],
        ['member' => EnsureUserIsAuthenticated::class.'::handle', 'path' => 'src/Http/Middleware/EnsureUserIsAuthenticated.php', 'line' => 76, 'kind' => 'human-or-mode-gate'],
        ['member' => ManagedAccountAccess::class.'::allows', 'path' => 'src/ManagedAccountAccess.php', 'line' => 11, 'kind' => 'managed-human-gate'],
        ['member' => ManagedFreshness::class.'::allows', 'path' => 'src/ManagedFreshness.php', 'line' => 29, 'kind' => 'managed-human-gate'],
        ['member' => StandaloneRouteOwnership::class.'::assertMatched', 'path' => 'src/StandaloneRouteOwnership.php', 'line' => 264, 'kind' => 'route-ownership-assertion'],
        ['member' => StandaloneRouteOwnership::class.'::assertOwned', 'path' => 'src/StandaloneRouteOwnership.php', 'line' => 218, 'kind' => 'route-ownership-assertion'],
        ['member' => StandaloneRouteOwnership::class.'::assertPackageMiddlewareMatched', 'path' => 'src/StandaloneRouteOwnership.php', 'line' => 194, 'kind' => 'route-ownership-assertion'],
        ['member' => StandaloneRouteOwnership::class.'::assertPackageMiddlewareOwned', 'path' => 'src/StandaloneRouteOwnership.php', 'line' => 168, 'kind' => 'route-ownership-assertion'],
    ];
    $inventory = UiEnforcementInventory::discover(dirname(__DIR__).'/src');

    expect($inventory)->toBe($expected)
        ->and($inventory)->toHaveCount(11)
        ->and(array_keys(p5fEnforcementDisposition()))->toBe(array_column($expected, 'member'));
});

it('fails the frozen inventory when a rogue twelfth direct gate appears', function (): void {
    $inventory = UiEnforcementInventory::discover(
        dirname(__DIR__).'/src',
        [__DIR__.'/InventoryFixtures/UiConditionedHumanGate.php'],
    );

    expect($inventory)->toHaveCount(12)
        ->and(array_column($inventory, 'member'))->toContain(UiConditionedHumanGate::class.'::handle')
        ->and(array_column($inventory, 'member'))->not->toBe(array_keys(p5fEnforcementDisposition()));
});
