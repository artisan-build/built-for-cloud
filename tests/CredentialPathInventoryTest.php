<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\CredentialPathInventory;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\DeviceCompositionOutsidePair;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\SecondStoreResolver;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\UnguardedCredentialAuthenticator;

/** @param list<string> $items @return list<string> */
function sortedCredentialInventory(array $items): array
{
    sort($items);

    return $items;
}

/** @return list<string> */
function frozenCredentialPathRows(): array
{
    return sortedCredentialInventory([
        'path:Basic|ArtisanBuild\BuiltForCloud\Auth\BasicAuthenticator|CredentialKind::Basic+secret_hash|CredentialResolver::resolve',
        'path:Bearer|ArtisanBuild\BuiltForCloud\Auth\BearerAuthenticator|CredentialKind::Bearer+secret_hash|CredentialResolver::resolve',
        'path:MCP|Http\Middleware\AuthenticateMcp:store-bearer+v4.public|CredentialKind::Bearer/DelegatedActor|TokenRegistry::resolveModel/AssertionVerifier+ConsoleKeyring',
        'path:HMAC|Http\Middleware\VerifyHmacSignature+Hmac\HmacVerifier|CredentialKind::Hmac+secret_ciphertext+secret_key_version|HmacVerifier::verify',
        'path:asymmetric|Actions\MintCredential::mintEnrollment|CredentialKind::Asymmetric+public_key:null|no-verifier',
        'path:enrollment|OnboardingToken+POST:/bfc/claim,/bfc/onboarding/issue,/exchange,/verify|DeliveryShape::EnrollmentCode|CredentialResolver::resolve-after-exchange',
        'path:device|enrollment+(external_consumer,installation)|DeliveryShape::EnrollmentCode|as-enrollment-partial',
        'path:system|SubjectType::Operator/Application/Installation+AuditActorType::CliOperator|CredentialKind::Bearer/Basic|CredentialResolver::resolve',
    ]);
}

/** @return list<string> */
function frozenTransitionalRows(): array
{
    $commands = sortedCredentialInventory([
        'command:ArtisanBuild\BuiltForCloud\Commands\FallbackTokenGenerateCommand=fallback-token:generate',
        'command:ArtisanBuild\BuiltForCloud\Commands\TokenCreateCommand=token:create',
        'command:ArtisanBuild\BuiltForCloud\Commands\TokenListCommand=token:list',
        'command:ArtisanBuild\BuiltForCloud\Commands\TokenRevokeCommand=token:revoke',
        'command:ArtisanBuild\BuiltForCloud\Commands\TokenRevokeSelfCommand=bfc:token:revoke-self',
        'command:ArtisanBuild\BuiltForCloud\Commands\TokenRotateCommand=token:rotate',
        'command:ArtisanBuild\BuiltForCloud\Commands\TokenUsageCommand=token:usage',
    ]);

    return sortedCredentialInventory([
        'transitional:ApiTokenMinter=>ApiToken(api_tokens)',
        'transitional:Audit\AppActorType::LegacyApiToken',
        'transitional:AuditActorType::AdminToken',
        'transitional:EnsureAdminToken@bfc.token.admin',
        'transitional:TokenRegistry-secret-resolution-service',
        'transitional:commands['.implode(',', $commands).']',
    ]);
}

/** @return list<string> */
function frozenCredentialClassification(): array
{
    return sortedCredentialInventory([
        'enum:ArtisanBuild\BuiltForCloud\AuditActorType::AdminToken=admin_token',
        'enum:ArtisanBuild\BuiltForCloud\AuditActorType::BoundUser=bound_user',
        'enum:ArtisanBuild\BuiltForCloud\AuditActorType::CliOperator=cli_operator',
        'enum:ArtisanBuild\BuiltForCloud\AuditActorType::CredentialHolder=credential_holder',
        'enum:ArtisanBuild\BuiltForCloud\AuditActorType::OperatorIntegration=operator_integration',
        'enum:ArtisanBuild\BuiltForCloud\Audit\AppActorType::ApiToken=api_token',
        'enum:ArtisanBuild\BuiltForCloud\Audit\AppActorType::DelegatedActor=delegated_actor',
        'enum:ArtisanBuild\BuiltForCloud\Audit\AppActorType::LegacyApiToken=legacy_api_token',
        'enum:ArtisanBuild\BuiltForCloud\Audit\AppActorType::LocalUser=local_user',
        'enum:ArtisanBuild\BuiltForCloud\SubjectType::Application=application',
        'enum:ArtisanBuild\BuiltForCloud\SubjectType::ExternalConsumer=external_consumer',
        'enum:ArtisanBuild\BuiltForCloud\SubjectType::Installation=installation',
        'enum:ArtisanBuild\BuiltForCloud\SubjectType::Operator=operator',
        'enum:ArtisanBuild\BuiltForCloud\SubjectType::UserPrincipal=user_principal',
        'command:ArtisanBuild\BuiltForCloud\Commands\ConsoleReKeyCommand=bfc:console:re-key',
        'command:ArtisanBuild\BuiltForCloud\Commands\ConsoleRetireKeyCommand=bfc:console:retire-key',
        'command:ArtisanBuild\BuiltForCloud\Commands\CreateAdminCommand=create-admin',
        'command:ArtisanBuild\BuiltForCloud\Commands\CredentialActivateCommand=bfc:credential:activate',
        'command:ArtisanBuild\BuiltForCloud\Commands\CredentialListCommand=bfc:credential:list',
        'command:ArtisanBuild\BuiltForCloud\Commands\CredentialMintCommand=bfc:credential:mint',
        'command:ArtisanBuild\BuiltForCloud\Commands\CredentialRevokeCommand=bfc:credential:revoke',
        'command:ArtisanBuild\BuiltForCloud\Commands\CredentialRotateCommand=bfc:credential:rotate',
        'command:ArtisanBuild\BuiltForCloud\Commands\FallbackTokenGenerateCommand=fallback-token:generate',
        'command:ArtisanBuild\BuiltForCloud\Commands\HmacRewrapCommand=bfc:hmac:rewrap',
        'command:ArtisanBuild\BuiltForCloud\Commands\InstallOperatorCredentialCommand=bfc:install:operator-credential',
        'command:ArtisanBuild\BuiltForCloud\Commands\OutboxDrainCommand=bfc:outbox:drain',
        'command:ArtisanBuild\BuiltForCloud\Commands\OwnershipMintClaimCommand=bfc:ownership:mint-claim',
        'command:ArtisanBuild\BuiltForCloud\Commands\OwnershipRemintOwnerTokenCommand=bfc:ownership:remint-owner-token',
        'command:ArtisanBuild\BuiltForCloud\Commands\SubjectOffboardCommand=bfc:subject:offboard',
        'command:ArtisanBuild\BuiltForCloud\Commands\TokenCreateCommand=token:create',
        'command:ArtisanBuild\BuiltForCloud\Commands\TokenListCommand=token:list',
        'command:ArtisanBuild\BuiltForCloud\Commands\TokenRevokeCommand=token:revoke',
        'command:ArtisanBuild\BuiltForCloud\Commands\TokenRevokeSelfCommand=bfc:token:revoke-self',
        'command:ArtisanBuild\BuiltForCloud\Commands\TokenRotateCommand=token:rotate',
        'command:ArtisanBuild\BuiltForCloud\Commands\TokenUsageCommand=token:usage',
        'command:ArtisanBuild\BuiltForCloud\Commands\WarnExpiringCredentialsCommand=bfc:credentials:warn-expiring',
    ]);
}

/**
 * P5-AC1's oracle is Part 1.1 plus Part 1.2b, while the independently
 * asserted root inventories keep row classification from hiding a newly
 * discovered mechanism. CredentialPathInventory documents the static-only
 * and partial-device limits that bound this proof.
 */
it('derives the frozen eight paths plus exactly six transitional rows from all five roots', function (): void {
    $inventory = CredentialPathInventory::discover(dirname(__DIR__).'/src');
    $expectedRows = sortedCredentialInventory([...frozenCredentialPathRows(), ...frozenTransitionalRows()]);
    $derivedRows = sortedCredentialInventory([...$inventory['paths'], ...$inventory['transitional']]);

    expect($inventory['violations'])->toBe([])
        ->and($derivedRows)->toBe($expectedRows)
        ->and($inventory['paths'])->toHaveCount(8)
        ->and($inventory['transitional'])->toHaveCount(6)
        ->and($inventory['mechanisms'])->toBe(sortedCredentialInventory([
            'authenticator:ArtisanBuild\BuiltForCloud\Auth\BasicAuthenticator',
            'authenticator:ArtisanBuild\BuiltForCloud\Auth\BearerAuthenticator',
            'guard:ArtisanBuild\BuiltForCloud\Auth\CredentialGuard',
            'guard:ArtisanBuild\BuiltForCloud\Console\ConsoleGuard',
            'key-sink:ArtisanBuild\BuiltForCloud\Hmac\HmacSigner',
            'key-sink:ArtisanBuild\BuiltForCloud\Hmac\HmacVerifier',
            'middleware:ArtisanBuild\BuiltForCloud\Http\Middleware\AuthenticateMcp',
            'middleware:ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureAdminToken',
            'middleware:ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureConsoleSession',
            'middleware:ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAbility',
            'middleware:ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin',
            'middleware:ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureManagedAuthority',
            'middleware:ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureStandaloneAuthority',
            'middleware:ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAdmin',
            'middleware:ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAuthenticated',
            'middleware:ArtisanBuild\BuiltForCloud\Http\Middleware\ExpireStandaloneHandoffOnRefusal',
            'middleware:ArtisanBuild\BuiltForCloud\Http\Middleware\UniformConsoleKeyRefusal',
            'middleware:ArtisanBuild\BuiltForCloud\Http\Middleware\VerifyHmacSignature',
            'resolver-service:ArtisanBuild\BuiltForCloud\Auth\CredentialResolver',
            'resolver-service:ArtisanBuild\BuiltForCloud\Console\AssertionVerifier',
            'resolver-service:ArtisanBuild\BuiltForCloud\Hmac\HmacVerifier',
            'resolver-service:ArtisanBuild\BuiltForCloud\TokenRegistry',
            'resolver:ArtisanBuild\BuiltForCloud\Auth\CredentialResolver',
        ]))
        ->and($inventory['lifecycle'])->toBe(sortedCredentialInventory([
            'action:ArtisanBuild\BuiltForCloud\Actions\ActivateCredential::__invoke',
            'action:ArtisanBuild\BuiltForCloud\Actions\ListCredentials::__invoke',
            'action:ArtisanBuild\BuiltForCloud\Actions\MintCredential::__invoke',
            'action:ArtisanBuild\BuiltForCloud\Actions\MintCredential::mintEnrollment',
            'action:ArtisanBuild\BuiltForCloud\Actions\OffboardSubject::__invoke',
            'action:ArtisanBuild\BuiltForCloud\Actions\RevokeCredential::__invoke',
            'action:ArtisanBuild\BuiltForCloud\Actions\RotateCredential::__invoke',
            'action:ArtisanBuild\BuiltForCloud\Actions\RotateCredential::idForName',
            'minter:ArtisanBuild\BuiltForCloud\ApiTokenMinter=>ApiToken(api_tokens)',
            'minter:ArtisanBuild\BuiltForCloud\UnifiedStoreCredentialMinter=>Credential(credentials)',
        ]))
        ->and($inventory['enrollment'])->toBe(sortedCredentialInventory([
            'model:ArtisanBuild\BuiltForCloud\OnboardingToken',
            'route:POST /bfc/claim=>ArtisanBuild\BuiltForCloud\Http\Controllers\ManageOnboarding::claim',
            'route:POST /bfc/onboarding/exchange=>ArtisanBuild\BuiltForCloud\Http\Controllers\ManageOnboarding::exchange',
            'route:POST /bfc/onboarding/issue=>ArtisanBuild\BuiltForCloud\Http\Controllers\ManageOnboarding::issue',
            'route:POST /bfc/onboarding/verify=>ArtisanBuild\BuiltForCloud\Http\Controllers\ManageOnboarding::verify',
        ]))
        ->and($inventory['classification'])->toBe(frozenCredentialClassification())
        ->and($inventory['key_selection'])->toBe([
            'key-selection:ArtisanBuild\BuiltForCloud\Hmac\HmacSigner',
            'key-selection:ArtisanBuild\BuiltForCloud\Hmac\HmacVerifier',
        ])
        ->and($inventory['transition_members'])->toBe(sortedCredentialInventory([
            'command:ArtisanBuild\BuiltForCloud\Commands\FallbackTokenGenerateCommand=fallback-token:generate',
            'command:ArtisanBuild\BuiltForCloud\Commands\TokenCreateCommand=token:create',
            'command:ArtisanBuild\BuiltForCloud\Commands\TokenListCommand=token:list',
            'command:ArtisanBuild\BuiltForCloud\Commands\TokenRevokeCommand=token:revoke',
            'command:ArtisanBuild\BuiltForCloud\Commands\TokenRevokeSelfCommand=bfc:token:revoke-self',
            'command:ArtisanBuild\BuiltForCloud\Commands\TokenRotateCommand=token:rotate',
            'command:ArtisanBuild\BuiltForCloud\Commands\TokenUsageCommand=token:usage',
        ]));
});

it('reports all four deliberate controls through their assigned derivation roots', function (): void {
    $inventory = CredentialPathInventory::discover(
        dirname(__DIR__).'/src',
        [__DIR__.'/Fixtures'],
    );

    expect($inventory['violations'])->toContain(
        'unchoked-authenticator:'.UnguardedCredentialAuthenticator::class,
        'second-store-resolver:'.UnguardedCredentialAuthenticator::class.'=>'.SecondStoreResolver::class,
        'unlisted-enrollment-route:route:POST /bfc/unlisted-enrollment=>ArtisanBuild\BuiltForCloud\Http\Controllers\ManageOnboarding::exchange',
        'out-of-pair-device-composition:device-subject:ArtisanBuild\BuiltForCloud\SubjectType::UserPrincipal',
    )
        ->and($inventory['enrollment'])->toContain(
            'route:POST /bfc/unlisted-enrollment=>ArtisanBuild\BuiltForCloud\Http\Controllers\ManageOnboarding::exchange',
        )
        ->and($inventory['paths'])->not->toContain(
            'path:device|enrollment+(external_consumer,installation)|DeliveryShape::EnrollmentCode|as-enrollment-partial',
        )
        ->and(DeviceCompositionOutsidePair::DEVICE_SUBJECT_TYPES)->toBe([SubjectType::UserPrincipal]);
});
