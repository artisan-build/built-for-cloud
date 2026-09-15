<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Testing\HmacSecretSurfaceInventory;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\PlaintextHmacEgress;

it('derives HMAC plaintext access and permits only the authenticated transfer boundary', function (): void {
    $inventory = HmacSecretSurfaceInventory::discover(dirname(__DIR__).'/src');

    expect($inventory['plaintext_access'])->toContain(
        'ArtisanBuild\\BuiltForCloud\\Actions\\InstallHmacCredentialFromClaim::install',
        'ArtisanBuild\\BuiltForCloud\\Hmac\\HmacSigner::signBound',
        'ArtisanBuild\\BuiltForCloud\\Hmac\\HmacVerifier::verifyBound',
        'ArtisanBuild\\BuiltForCloud\\Http\\Controllers\\ManageOnboarding::deliverPendingSigningKey',
    )->and($inventory['allowed_egress'])->toBe([
        'ArtisanBuild\\BuiltForCloud\\HttpHmacCredentialIssuerClient::claim',
        'ArtisanBuild\\BuiltForCloud\\Http\\Controllers\\ManageOnboarding::deliverPendingSigningKey',
        'ArtisanBuild\\BuiltForCloud\\ImportedHmacSecret::reveal',
        'ArtisanBuild\\BuiltForCloud\\MintedSecret::reveal',
    ])->and($inventory['reported_egress'])->toBe([])
        ->and($inventory['process_arguments'])->toBe([])
        ->and($inventory['violations'])->toBe([])
        ->and($inventory['limits'])->toBe(HmacSecretSurfaceInventory::LIMITS);
});

it('reports the explicit plaintext return log serialization disk and process-argument positive control', function (): void {
    $member = PlaintextHmacEgress::class.'::leak';
    $inventory = HmacSecretSurfaceInventory::discover(
        dirname(__DIR__).'/src',
        [__DIR__.'/Fixtures/PlaintextHmacEgress.php'],
    );

    expect($inventory['reported_egress'])->toContain($member)
        ->and($inventory['process_arguments'])->toContain($member)
        ->and($inventory['violations'])->toContain(
            'plaintext-egress:'.$member,
            'plaintext-process-argument:'.$member,
        );
});
