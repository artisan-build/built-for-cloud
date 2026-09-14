<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AppPurposeRegistry;
use ArtisanBuild\BuiltForCloud\Testing\AppPurposeConsumerInventory;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\ListValuedAppPurposeConsumer;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\UnparsedAppPurposeConsumer;

it('derives the exact scalar and enum-parsed production app-purpose consumer set', function (): void {
    $inventory = AppPurposeConsumerInventory::discover(__DIR__.'/../src');

    expect($inventory['consumers'])->toBe([[
        'member' => AppPurposeRegistry::class.'::purpose',
        'reads' => 1,
        'scalar_entry' => true,
        'enum_parse' => true,
    ]])->and($inventory['violations'])->toBe([])
        ->and($inventory['limits'])->toBe(AppPurposeConsumerInventory::LIMITS);
});

it('reports a consumer that treats one map entry as a list', function (): void {
    $inventory = AppPurposeConsumerInventory::discover(
        __DIR__.'/../src',
        [__DIR__.'/Fixtures/ListValuedAppPurposeConsumer.php'],
    );

    expect($inventory['consumers'])->toContain([
        'member' => ListValuedAppPurposeConsumer::class.'::purposes',
        'reads' => 1,
        'scalar_entry' => false,
        'enum_parse' => true,
    ])->and($inventory['violations'])->toBe([
        'non-scalar-entry:'.ListValuedAppPurposeConsumer::class.'::purposes',
    ]);
});

it('reports a consumer that skips credential-purpose parsing', function (): void {
    $inventory = AppPurposeConsumerInventory::discover(
        __DIR__.'/../src',
        [__DIR__.'/Fixtures/UnparsedAppPurposeConsumer.php'],
    );

    expect($inventory['consumers'])->toContain([
        'member' => UnparsedAppPurposeConsumer::class.'::purpose',
        'reads' => 1,
        'scalar_entry' => true,
        'enum_parse' => false,
    ])->and($inventory['violations'])->toBe([
        'missing-credential-purpose-parse:'.UnparsedAppPurposeConsumer::class.'::purpose',
    ]);
});
