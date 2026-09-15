<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Testing\CredentialWriterInventory;

it('derives the exact production credential writers and their explicit purpose', function (): void {
    $inventory = CredentialWriterInventory::discover(__DIR__.'/../src');

    expect($inventory['writers'])->toBe([
        ['member' => 'ArtisanBuild\BuiltForCloud\Actions\MintCredential::mintEnrollment', 'has_purpose' => true],
        ['member' => 'ArtisanBuild\BuiltForCloud\Actions\MintCredential::mintSecretBearing', 'has_purpose' => true],
        ['member' => 'ArtisanBuild\BuiltForCloud\Actions\MintCredential::mintSigningKey', 'has_purpose' => true],
        ['member' => 'ArtisanBuild\BuiltForCloud\Actions\RotateCredential::replaceWithEnrollment', 'has_purpose' => true],
        ['member' => 'ArtisanBuild\BuiltForCloud\Actions\RotateCredential::replaceWithPendingSigningKey', 'has_purpose' => true],
        ['member' => 'ArtisanBuild\BuiltForCloud\Actions\RotateCredential::replaceWithSecret', 'has_purpose' => true],
        ['member' => 'ArtisanBuild\BuiltForCloud\OwnerCredentialMinter::mintFromHash', 'has_purpose' => true],
        ['member' => 'ArtisanBuild\BuiltForCloud\UnifiedStoreCredentialMinter::mint', 'has_purpose' => true],
    ])->and($inventory['violations'])->toBe([])
        ->and($inventory['excluded_classes'])->toBe([
            'ArtisanBuild\BuiltForCloud\Hmac\SigningRootLifecycle',
        ])
        ->and($inventory['limits'])->toBe(CredentialWriterInventory::LIMITS);
});

it('reports the rogue omitted-purpose writer positive control', function (): void {
    $inventory = CredentialWriterInventory::discover(
        __DIR__.'/../src',
        [__DIR__.'/Fixtures/RogueCredentialWriter.php'],
    );

    expect($inventory['writers'])->toContain([
        'member' => 'Fixtures\RogueCredentialWriter::write',
        'has_purpose' => false,
    ], [
        'member' => 'Fixtures\RogueCredentialWriter::writeThroughBoundHelper',
        'has_purpose' => false,
    ])->and($inventory['violations'])->toContain(
        'missing-purpose:Fixtures\RogueCredentialWriter::write',
        'missing-purpose:Fixtures\RogueCredentialWriter::writeThroughBoundHelper',
    );
});
