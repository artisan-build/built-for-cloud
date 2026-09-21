<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AppPurposeRegistry;
use ArtisanBuild\BuiltForCloud\Auth\BasicAuthenticator;
use ArtisanBuild\BuiltForCloud\Auth\BearerAuthenticator;
use ArtisanBuild\BuiltForCloud\Auth\CredentialGuard;
use ArtisanBuild\BuiltForCloud\Auth\CredentialResolver;
use ArtisanBuild\BuiltForCloud\BoundBearerCredentialAuthenticator;
use ArtisanBuild\BuiltForCloud\Console\AssertionVerifier;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\Hmac\HmacSigner;
use ArtisanBuild\BuiltForCloud\Hmac\HmacVerifier;
use ArtisanBuild\BuiltForCloud\Hmac\SigningRootMac;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageOnboarding;
use ArtisanBuild\BuiltForCloud\Http\Middleware\AuthenticateMcp;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCurrentOwnerCredential;
use ArtisanBuild\BuiltForCloud\ManagedAccountAccess;
use ArtisanBuild\BuiltForCloud\Testing\ProtocolUiGuardInventory;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\UiConditionedLifecycleRefusal;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\UiConditionedPurposeGate;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('copies and compares every inherited AC8 protocol disposition', function (): void {
    $inventory = ProtocolUiGuardInventory::compare(dirname(__DIR__).'/src');

    expect($inventory['resolver_callers'])->toBe([
        BasicAuthenticator::class.'::credential|expressions=1',
        BearerAuthenticator::class.'::credential|expressions=1',
        CredentialGuard::class.'::validate|expressions=2',
        BoundBearerCredentialAuthenticator::class.'::authenticate|expressions=1',
        ManageOnboarding::class.'::verifyUnifiedDurable|expressions=1',
        AuthenticateMcp::class.'::handle|expressions=1',
        EnsureCredentialAdmin::class.'::handle|expressions=1',
        EnsureCurrentOwnerCredential::class.'::handle|expressions=1',
    ])->and($inventory['resolver_expression_count'])->toBe(9)
        ->and($inventory['ordinary_hmac_selectors'])->toBe([
            HmacSigner::class.'::sign',
            HmacVerifier::class.'::verify',
        ])->and($inventory['app_purpose_consumers'])->toBe([
            AppPurposeRegistry::class.'::purpose',
        ])->and($inventory['root_selectors'])->toBe([
            SigningRootMac::class.'::mac',
            SigningRootMac::class.'::verify',
        ])->and($inventory['direct_members'])->toBe([
            CredentialResolver::class.'::resolve',
            ManagedAccountAccess::class.'::allowsCredential',
            HmacVerifier::class.'::verify',
            AssertionVerifier::class.'::verify',
        ])->and($inventory['forbidden_members'])->toHaveCount(16)
        ->and($inventory['ui_reads'])->toBe([])
        ->and($inventory['violations'])->toBe([]);
});

it('independently fails on the meaningful UI-conditioned purpose gate control', function (): void {
    $gate = new UiConditionedPurposeGate;
    config(['built-for-cloud.ui.personal_credentials' => false]);
    expect($gate->allows(CredentialPurpose::Consumption))->toBeFalse();
    config(['built-for-cloud.ui.personal_credentials' => true]);
    expect($gate->allows(CredentialPurpose::Consumption))->toBeTrue();

    $inventory = ProtocolUiGuardInventory::compare(
        dirname(__DIR__).'/src',
        [__DIR__.'/Fixtures/UiConditionedPurposeGate.php'],
        [UiConditionedPurposeGate::class.'::allows'],
    );

    expect($inventory['violations'])->toBe([
        'forbidden-ui-read:'.UiConditionedPurposeGate::class.'|built-for-cloud.ui.personal_credentials|1',
    ]);
});

it('independently fails on the meaningful UI-conditioned lifecycle refusal control', function (): void {
    $credential = new Credential;
    $credential->revoked_at = now();
    $gate = new UiConditionedLifecycleRefusal;

    config(['built-for-cloud.ui.session_management' => false]);
    $gate->assertUsable($credential);
    config(['built-for-cloud.ui.session_management' => true]);
    expect(fn () => $gate->assertUsable($credential))->toThrow(RuntimeException::class);

    $inventory = ProtocolUiGuardInventory::compare(
        dirname(__DIR__).'/src',
        [__DIR__.'/Fixtures/UiConditionedLifecycleRefusal.php'],
        [UiConditionedLifecycleRefusal::class.'::assertUsable'],
    );

    expect($inventory['violations'])->toBe([
        'forbidden-ui-read:'.UiConditionedLifecycleRefusal::class.'|built-for-cloud.ui.session_management|1',
    ]);
});
