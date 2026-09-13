<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Testing\CredentialPathInventory;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\ClassBoundCredentialGate;
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
        'path:Basic|ArtisanBuild\BuiltForCloud\Auth\BasicAuthenticator',
        'path:Bearer|ArtisanBuild\BuiltForCloud\Auth\BearerAuthenticator',
        'path:MCP|Http\Middleware\AuthenticateMcp:store-bearer+v4.public',
        'path:HMAC|Http\Middleware\VerifyHmacSignature+Hmac\HmacVerifier',
        'path:asymmetric|Actions\MintCredential::mintEnrollment',
        'path:enrollment|OnboardingToken+POST:/bfc/claim,/bfc/onboarding/issue,/exchange,/verify',
        'path:system|SubjectType::Operator/Application/Installation+AuditActorType::CliOperator',
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
        'enum:ArtisanBuild\BuiltForCloud\AuditActorType::BoundUser=bound_user',
        'enum:ArtisanBuild\BuiltForCloud\AuditActorType::CliOperator=cli_operator',
        'enum:ArtisanBuild\BuiltForCloud\AuditActorType::CredentialHolder=credential_holder',
        'enum:ArtisanBuild\BuiltForCloud\AuditActorType::OperatorIntegration=operator_integration',
        'enum:ArtisanBuild\BuiltForCloud\Audit\AppActorType::ApiToken=api_token',
        'enum:ArtisanBuild\BuiltForCloud\Audit\AppActorType::DelegatedActor=delegated_actor',
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
        'command:ArtisanBuild\BuiltForCloud\Commands\HmacRewrapCommand=bfc:hmac:rewrap',
        'command:ArtisanBuild\BuiltForCloud\Commands\InstallOperatorCredentialCommand=bfc:install:operator-credential',
        'command:ArtisanBuild\BuiltForCloud\Commands\OutboxDrainCommand=bfc:outbox:drain',
        'command:ArtisanBuild\BuiltForCloud\Commands\OwnershipMintClaimCommand=bfc:ownership:mint-claim',
        'command:ArtisanBuild\BuiltForCloud\Commands\OwnershipRemintOwnerTokenCommand=bfc:ownership:remint-owner-token',
        'command:ArtisanBuild\BuiltForCloud\Commands\SubjectOffboardCommand=bfc:subject:offboard',
        'command:ArtisanBuild\BuiltForCloud\Commands\WarnExpiringCredentialsCommand=bfc:credentials:warn-expiring',
    ]);
}

/**
 * P5-AC12's oracle is Part 1.1's seven discoverable path identities with
 * every Part 1.2b row undiscovered, while the independently
 * asserted root inventories keep row classification from hiding a newly
 * discovered mechanism. CredentialPathInventory documents the static-only
 * limits and the unenforced, non-discovered device binding that bound this
 * proof.
 */
it('derives the seven discoverable paths with no transitional rows from all five roots', function (): void {
    $inventory = CredentialPathInventory::discover(dirname(__DIR__).'/src');
    $expectedRows = frozenCredentialPathRows();
    $derivedRows = sortedCredentialInventory([...$inventory['paths'], ...$inventory['transitional']]);

    expect($inventory['violations'])->toBe([])
        ->and($derivedRows)->toBe($expectedRows)
        ->and($inventory['paths'])->toHaveCount(7)
        ->and($inventory['transitional'])->toBe([])
        ->and($inventory['mechanisms'])->toBe(sortedCredentialInventory([
            'authenticator:ArtisanBuild\BuiltForCloud\Auth\BasicAuthenticator',
            'authenticator:ArtisanBuild\BuiltForCloud\Auth\BearerAuthenticator',
            'guard:ArtisanBuild\BuiltForCloud\Auth\CredentialGuard',
            'guard:ArtisanBuild\BuiltForCloud\Console\ConsoleGuard',
            'key-sink:ArtisanBuild\BuiltForCloud\Hmac\HmacSigner',
            'key-sink:ArtisanBuild\BuiltForCloud\Hmac\HmacVerifier',
            'middleware:ArtisanBuild\BuiltForCloud\Http\Middleware\AuthenticateMcp',
            'middleware:ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureConsoleSession',
            'middleware:ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAbility',
            'middleware:ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin',
            'middleware:ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureDashboardCredential',
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
            'minter:ArtisanBuild\BuiltForCloud\UnifiedStoreCredentialMinter=>Credential(credentials)',
        ]))
        ->and($inventory['enrollment'])->toBe(sortedCredentialInventory([
            'model:ArtisanBuild\BuiltForCloud\OnboardingToken',
            'route:POST /bfc/claim=>ArtisanBuild\BuiltForCloud\Http\Controllers\ManageOnboarding::claim',
            'route:POST /bfc/onboarding/exchange=>ArtisanBuild\BuiltForCloud\Http\Controllers\ManageOnboarding::exchange',
            'route:POST /bfc/onboarding/issue=>ArtisanBuild\BuiltForCloud\Http\Controllers\ManageOnboarding::issue',
            'route:POST /bfc/onboarding/verify=>ArtisanBuild\BuiltForCloud\Http\Controllers\ManageOnboarding::verify',
        ]))
        ->and($inventory['enrollment_properties'])->toBe([
            'enrollment-code:hash-only',
            'enrollment-code:revocable',
            'enrollment-code:short-lived',
            'enrollment-code:single-use',
        ])
        ->and($inventory['classification'])->toBe(frozenCredentialClassification())
        ->and($inventory['key_selection'])->toBe([
            'key-selection:ArtisanBuild\BuiltForCloud\Hmac\HmacSigner',
            'key-selection:ArtisanBuild\BuiltForCloud\Hmac\HmacVerifier',
        ])
        ->and($inventory['resolution_choke_points'])->toBe([
            'choke-point:ArtisanBuild\BuiltForCloud\Auth\CredentialResolver::resolve',
            'choke-point:ArtisanBuild\BuiltForCloud\Hmac\HmacVerifier::verify',
        ])
        ->and($inventory['transition_members'])->toBe([])
        ->and(array_intersect($inventory['transitional'], frozenTransitionalRows()))->toBe([]);
});

it('reports all four deliberate controls through their assigned derivation roots', function (): void {
    $inventory = CredentialPathInventory::discover(
        dirname(__DIR__).'/src',
        [__DIR__.'/Fixtures'],
    );
    $production = CredentialPathInventory::discover(dirname(__DIR__).'/src');
    $unexpectedMiddleware = array_values(array_diff(
        array_values(array_filter($inventory['mechanisms'], static fn (string $item): bool => str_starts_with($item, 'middleware:'))),
        array_values(array_filter($production['mechanisms'], static fn (string $item): bool => str_starts_with($item, 'middleware:'))),
    ));
    $devicePaths = array_values(array_filter(
        $inventory['paths'],
        static fn (string $item): bool => str_starts_with($item, 'path:device|'),
    ));

    expect($inventory['violations'])->toContain(
        'unchoked-authenticator:'.UnguardedCredentialAuthenticator::class,
        'second-store-resolver:'.UnguardedCredentialAuthenticator::class.'=>'.SecondStoreResolver::class,
        'unlisted-enrollment-route:route:POST /bfc/unlisted-enrollment=>ArtisanBuild\BuiltForCloud\Http\Controllers\ManageOnboarding::exchange',
    )
        ->and($inventory['enrollment'])->toContain(
            'route:POST /bfc/unlisted-enrollment=>ArtisanBuild\BuiltForCloud\Http\Controllers\ManageOnboarding::exchange',
        )
        ->and($unexpectedMiddleware)->toBe(['middleware:'.ClassBoundCredentialGate::class])
        ->and($devicePaths)->toBe([]);
});

it('reports a second credential store across query forms', function (string $query): void {
    $root = sys_get_temp_dir().'/bfc-second-store-control-'.bin2hex(random_bytes(8));
    $namespace = 'ArtisanBuild\\BuiltForCloud\\Tests\\SecondStoreControl';

    mkdir($root, 0777, true);
    file_put_contents($root.'/ProbeAuthenticator.php', <<<PHP
<?php
namespace {$namespace};
use ArtisanBuild\BuiltForCloud\Contracts\CredentialAuthenticator;
use ArtisanBuild\BuiltForCloud\Credential;
use Illuminate\Http\Request;
final class ProbeAuthenticator implements CredentialAuthenticator
{
    public function __construct(private ProbeResolver \$resolver) {}
    public function credential(Request \$request): ?Credential
    {
        \$this->resolver->resolve(\$request->bearerToken() ?? '');
        return null;
    }
}
PHP);
    file_put_contents($root.'/ProbeResolver.php', <<<PHP
<?php
namespace {$namespace};
final class ProbeResolver
{
    public function resolve(string \$secret): mixed
    {
        \$hash = hash('sha256', \$secret);
        return {$query};
    }
}
PHP);

    $inventory = CredentialPathInventory::discover(dirname(__DIR__).'/src', [$root]);

    expect($inventory['violations'])->toContain(
        'second-store-resolver:'.$namespace.'\\ProbeAuthenticator=>'.$namespace.'\\ProbeResolver',
    );
})->with([
    'model query and where' => "OtherStoreRecord::query()->where('token_hash', \$hash)->first()",
    'direct model where' => "OtherStoreRecord::where('token_hash', \$hash)->first()",
    'model firstWhere' => "OtherStoreRecord::query()->firstWhere('token_hash', \$hash)",
    'different hash column' => "OtherStoreRecord::query()->where('hash', \$hash)->first()",
    'raw select' => "DB::selectOne('select * from other_store where token_hash = ?', [\$hash])",
    'qualified credential model' => "\\Vendor\\Legacy\\Credential::query()->where('token_hash', \$hash)->first()",
    'named connection' => "DB::connection('legacy')->table('credentials')->where('secret_hash', \$hash)->first()",
    'array where' => "OtherStoreRecord::query()->where(['token_hash' => \$hash])->first()",
    'query builder table' => "DB::table('other_store')->where('token_hash', \$hash)->first()",
]);
