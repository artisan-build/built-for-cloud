<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Testing\SigningRootDisclosureInventory;
use ArtisanBuild\BuiltForCloud\Testing\SigningRootInventory;

it('derives the exact signing-root producer selectors decrypt dispositions and delegation', function (): void {
    $inventory = SigningRootInventory::discover(dirname(__DIR__).'/src');

    expect($inventory['producers'])->toBe([
        'ArtisanBuild\\BuiltForCloud\\Hmac\\SigningRootLifecycle::createRoot',
    ])->and($inventory['producer_dispositions'])->toBe([
        'ArtisanBuild\\BuiltForCloud\\Hmac\\SigningRootLifecycle::createRoot|direct-active-encrypted',
    ])->and($inventory['selectors'])->toBe([
        'ArtisanBuild\\BuiltForCloud\\Hmac\\SigningRootMac::mac',
        'ArtisanBuild\\BuiltForCloud\\Hmac\\SigningRootMac::verify',
    ])->and($inventory['selector_dispositions'])->toBe([
        'ArtisanBuild\\BuiltForCloud\\Hmac\\SigningRootMac::mac|current-only|identity-before-decrypt|input=bytes|result={keyId,lowercaseHexMac}',
        'ArtisanBuild\\BuiltForCloud\\Hmac\\SigningRootMac::verify|named-current-or-grace|identity-before-decrypt|result=bool',
    ])->and($inventory['hmac_decrypt_sites'])->toBe([
        'ArtisanBuild\\BuiltForCloud\\Commands\\HmacRewrapCommand::rewrap',
        'ArtisanBuild\\BuiltForCloud\\Hmac\\HmacSigner::sign',
        'ArtisanBuild\\BuiltForCloud\\Hmac\\HmacSigner::signBound',
        'ArtisanBuild\\BuiltForCloud\\Hmac\\HmacVerifier::verify',
        'ArtisanBuild\\BuiltForCloud\\Hmac\\HmacVerifier::verifyBound',
        'ArtisanBuild\\BuiltForCloud\\Hmac\\SigningRootMac::mac',
        'ArtisanBuild\\BuiltForCloud\\Hmac\\SigningRootMac::verify',
        'ArtisanBuild\\BuiltForCloud\\Http\\Controllers\\ManageOnboarding::deliverPendingSigningKey',
    ])->and($inventory['root_decrypt_sites'])->toBe([
        'ArtisanBuild\\BuiltForCloud\\Commands\\HmacRewrapCommand::rewrap',
        'ArtisanBuild\\BuiltForCloud\\Hmac\\SigningRootMac::mac',
        'ArtisanBuild\\BuiltForCloud\\Hmac\\SigningRootMac::verify',
    ])->and($inventory['delegations'])->toBe([
        'ArtisanBuild\\BuiltForCloud\\Actions\\RotateCredential::__invoke',
    ])->and($inventory['violations'])->toBe([])
        ->and($inventory['limits'])->toBe(SigningRootInventory::LIMITS);
});

it('fails comparison for every required signing-root positive control', function (): void {
    $fixtures = __DIR__.'/Fixtures/SigningRoot';
    $inventory = SigningRootInventory::discover(dirname(__DIR__).'/src', [$fixtures]);

    expect($inventory['violations'])->toContain(
        'unexpected-root-decrypt:ArtisanBuild\\BuiltForCloud\\Tests\\Fixtures\\SigningRoot\\PurposeOmittedRootSelector::select',
        'root-selector-order:ArtisanBuild\\BuiltForCloud\\Tests\\Fixtures\\SigningRoot\\PurposeOmittedRootSelector::select',
        'unexpected-root-decrypt:ArtisanBuild\\BuiltForCloud\\Tests\\Fixtures\\SigningRoot\\PlaintextReturningRootAction::reveal',
        'unexpected-root-producer:ArtisanBuild\\BuiltForCloud\\Tests\\Fixtures\\SigningRoot\\OrdinarySigningRootReplacement::replace',
        'root-producer-disposition:ArtisanBuild\\BuiltForCloud\\Tests\\Fixtures\\SigningRoot\\OrdinarySigningRootReplacement::replace|ordinary-or-unclassified',
    );
});

it('derives material-free delivery summary list audit command and HTTP surfaces', function (): void {
    $inventory = SigningRootDisclosureInventory::discover(dirname(__DIR__).'/src');

    expect($inventory['delivery_shapes'])->toBe([
        'basic_auth',
        'bearer',
        'enrollment_code',
        'none',
        'signing_key',
        'signing_key_code',
    ])->and($inventory['root_returns'])->toBe([
        'ArtisanBuild\\BuiltForCloud\\Hmac\\SigningRootLifecycle::provision|delivery=none',
        'ArtisanBuild\\BuiltForCloud\\Hmac\\SigningRootLifecycle::rotate|delivery=none',
    ])->and($inventory['summary_fields'])->toBe([
        'id', 'kind', 'purpose', 'subject_type', 'subject_ref', 'name', 'abilities', 'status',
        'created_at', 'last_used_at', 'expires_at', 'revoked_at', 'rotated_at',
        'presentation_cadence_seconds', 'unsupported',
    ])->and($inventory['list_exclusions'])->toBe([
        'ArtisanBuild\\BuiltForCloud\\Actions\\ListCredentials::__invoke',
        'ArtisanBuild\\BuiltForCloud\\CredentialManagementScope::apply',
    ])->and($inventory['audit_writes'])->toBe([
        'ArtisanBuild\\BuiltForCloud\\Hmac\\SigningRootLifecycle::provision|writes=1|note=absent',
        'ArtisanBuild\\BuiltForCloud\\Hmac\\SigningRootLifecycle::rotate|writes=2|note=absent',
    ])->and($inventory['command_surfaces'])->toBe([
        'ArtisanBuild\\BuiltForCloud\\Commands\\CredentialRotateCommand=bfc:credential:rotate',
        'ArtisanBuild\\BuiltForCloud\\Commands\\SigningRootProvisionCommand=bfc:signing-root:provision',
    ])->and($inventory['http_surfaces'])->toBe([
        'ArtisanBuild\\BuiltForCloud\\Http\\Controllers\\ManageCredentials::rotate',
    ])
        ->and($inventory['surface_leaks'])->toBe([])
        ->and($inventory['violations'])->toBe([])
        ->and($inventory['limits'])->toBe(SigningRootDisclosureInventory::LIMITS);
});

it('reports plaintext and ordinary-delivery fixtures through the surface-leak inventory', function (): void {
    $inventory = SigningRootDisclosureInventory::discover(
        dirname(__DIR__).'/src',
        [__DIR__.'/Fixtures/SigningRoot'],
    );

    expect($inventory['surface_leaks'])->toContain(
        'ArtisanBuild\\BuiltForCloud\\Tests\\Fixtures\\SigningRoot\\PlaintextReturningRootAction::reveal',
        'ArtisanBuild\\BuiltForCloud\\Tests\\Fixtures\\SigningRoot\\PurposeOmittedRootSelector::select',
        'ArtisanBuild\\BuiltForCloud\\Tests\\Fixtures\\SigningRoot\\OrdinarySigningRootReplacement::replace',
    )->and($inventory['violations'])->toContain(
        'root-surface-leak:ArtisanBuild\\BuiltForCloud\\Tests\\Fixtures\\SigningRoot\\PlaintextReturningRootAction::reveal',
        'root-surface-leak:ArtisanBuild\\BuiltForCloud\\Tests\\Fixtures\\SigningRoot\\OrdinarySigningRootReplacement::replace',
    );
});
