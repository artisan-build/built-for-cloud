<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use ArtisanBuild\BuiltForCloud\Contracts\IdentityContext;
use ArtisanBuild\BuiltForCloud\CredentialOwnership;
use ArtisanBuild\BuiltForCloud\DomainIdentityContext;
use ArtisanBuild\BuiltForCloud\Exceptions\UnsupportedHumanAuthConfiguration;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\RolePolicy;
use ArtisanBuild\BuiltForCloud\Testing\ContextContractScan;
use ArtisanBuild\BuiltForCloud\Testing\ThinHostConformance;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\ReelProtectionDecision;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RogueIdentityContext;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Schema;

uses(RefreshDatabase::class);

it('migrates the canonical user schema with stable attribution and nullable password', function (): void {
    $columns = Schema::getColumnListing('users');

    expect($columns)->toContain(
        'id',
        'email',
        'password',
        'role',
        'status',
        'scalpels_issuer',
        'scalpels_connection_id',
        'scalpels_id',
        'original_contact_email',
        'email_is_generated',
        'last_authenticated_at',
        'membership_confirmed_at',
        'membership_checked_at',
        'membership_response_at',
        'deactivated_at',
    );

    $user = User::query()->create(['name' => 'Stable', 'email' => 'stable@example.test']);
    $stableId = $user->getKey();

    $user->forceFill(['email' => 'changed@example.test'])->save();

    expect($user->password)->toBeNull()
        ->and($user->refresh()->getKey())->toBe($stableId)
        ->and(Schema::getColumnType('users', 'role', true))->not->toContain('enum');
});

it('enforces separate email and trusted external identity uniqueness in the database', function (): void {
    User::query()->create(['name' => 'Email One', 'email' => 'same@example.test']);

    expect(fn () => User::query()->create(['name' => 'Email Two', 'email' => 'same@example.test']))
        ->toThrow(QueryException::class);

    User::query()->create(['name' => 'External One', 'email' => 'external-one@example.test'])
        ->forceFill([
            'scalpels_issuer' => 'https://scalpels.example',
            'scalpels_connection_id' => 'connection-1',
            'scalpels_id' => 'subject-1',
        ])->save();

    expect(function (): void {
        User::query()->create(['name' => 'External Two', 'email' => 'external-two@example.test'])
            ->forceFill([
                'scalpels_issuer' => 'https://scalpels.example',
                'scalpels_connection_id' => 'connection-1',
                'scalpels_id' => 'subject-1',
            ])->save();
    })->toThrow(QueryException::class);
});

it('round trips source contact address and generated email as distinct facts', function (): void {
    $user = User::query()->create([
        'name' => 'Collision',
        'email' => 'person+bfc-candidate@example.test',
    ])->forceFill([
        'original_contact_email' => 'person@example.test',
        'email_is_generated' => true,
    ]);
    $user->save();

    expect($user->refresh()->email)->toBe('person+bfc-candidate@example.test')
        ->and($user->original_contact_email)->toBe('person@example.test')
        ->and($user->email_is_generated)->toBeTrue();
});

it('uses the canonical model through Laravel session provider retrieval and login', function (): void {
    $user = User::query()->create([
        'name' => 'Session User',
        'email' => 'session@example.test',
        'password' => Hash::make('secret-password'),
    ]);
    $guard = Auth::guard('web');
    $provider = $guard->getProvider();
    $retrieved = $provider->retrieveByCredentials(['email' => 'session@example.test']);

    expect(config('auth.providers.users.model'))->toBe(User::class)
        ->and($retrieved)->toBeInstanceOf(User::class)
        ->and($provider->validateCredentials($retrieved, ['password' => 'secret-password']))->toBeTrue();

    $guard->login($user);

    expect($guard->check())->toBeTrue()
        ->and((string) $guard->id())->toBe((string) $user->getKey());
});

it('fails loudly at boot for a conflicting configured human model', function (): void {
    config()->set('auth.providers.users.model', ArtisanBuild\BuiltForCloud\Tests\Fixtures\User::class);

    expect(fn () => (new BuiltForCloudServiceProvider(app()))->boot())
        ->toThrow(UnsupportedHumanAuthConfiguration::class, 'Conflicting provider');
});

it('enforces every closed role decision and denies unknown roles', function (
    UserRole|string $role,
    bool $useProduct,
    bool $manageMembers,
    bool $manageAdmins,
    bool $transition,
    bool $sameActor,
    bool $otherActor,
): void {
    expect(RolePolicy::canUseProduct($role))->toBe($useProduct)
        ->and(RolePolicy::canManageMembers($role))->toBe($manageMembers)
        ->and(RolePolicy::canManageAdmins($role))->toBe($manageAdmins)
        ->and(RolePolicy::canInitiateModeTransition($role))->toBe($transition)
        ->and(RolePolicy::isSameActorOrAdminOrOwner($role, 'actor-1', 'actor-1'))->toBe($sameActor)
        ->and(RolePolicy::isSameActorOrAdminOrOwner($role, 'actor-1', 'actor-2'))->toBe($otherActor)
        ->and(RolePolicy::canManage($role, UserRole::Owner))->toBeFalse();
})->with([
    'Owner' => [UserRole::Owner, true, true, true, true, true, true],
    'Admin' => [UserRole::Admin, true, true, false, false, true, true],
    'Member' => [UserRole::Member, true, false, false, false, true, false],
    'unknown' => ['super-admin', false, false, false, false, false, false],
]);

it('keeps domain identity immutable and opaque across recreated contexts', function (): void {
    $first = new DomainIdentityContext(
        'stable-local-id',
        UserRole::Member,
        AuthorityMode::Managed,
        9,
        CredentialOwnership::Account,
    );
    $recreated = new DomainIdentityContext(
        'stable-local-id',
        UserRole::Member,
        AuthorityMode::Managed,
        9,
        CredentialOwnership::Account,
    );
    $other = new DomainIdentityContext(
        'other-id',
        UserRole::Member,
        AuthorityMode::Managed,
        9,
        CredentialOwnership::Account,
    );
    $admin = new DomainIdentityContext(
        'admin-id',
        UserRole::Admin,
        AuthorityMode::Managed,
        9,
        CredentialOwnership::Account,
    );

    expect((new ReelProtectionDecision($recreated))->canUnprotect($first->actorId()))->toBeTrue()
        ->and((new ReelProtectionDecision($other))->canUnprotect($first->actorId()))->toBeFalse()
        ->and((new ReelProtectionDecision($admin))->canUnprotect($first->actorId()))->toBeTrue()
        ->and($first->authorityGeneration())->toBe(9)
        ->and($first->credentialOwnership())->toBe(CredentialOwnership::Account);

    $constructorType = (new ReflectionClass(ReelProtectionDecision::class))
        ->getConstructor()?->getParameters()[0]->getType();

    expect((string) $constructorType)->toBe(IdentityContext::class)
        ->and(ContextContractScan::violations(IdentityContext::class))->toBe([])
        ->and(ContextContractScan::violations(RogueIdentityContext::class))->not->toBe([]);
});

it('stores one authority record and advances generation with compare and set', function (): void {
    expect(InstallationAuthority::query()->count())->toBe(1);

    $initial = InstallationAuthority::current();
    $changed = InstallationAuthority::change($initial, AuthorityMode::Managed);

    expect($initial->mode)->toBe(AuthorityMode::Standalone)
        ->and($initial->generation)->toBe(1)
        ->and($changed?->mode)->toBe(AuthorityMode::Managed)
        ->and($changed?->generation)->toBe(2)
        ->and(InstallationAuthority::change($initial, AuthorityMode::Managed))->toBeNull()
        ->and(InstallationAuthority::query()->count())->toBe(1);
});

it('denies every context decision for unknown authority mode', function (): void {
    $context = new DomainIdentityContext(
        'owner-id',
        UserRole::Owner,
        'unexpected',
        1,
        CredentialOwnership::Installation,
    );

    expect($context->authorityMode())->toBeNull()
        ->and($context->canUseProduct())->toBeFalse()
        ->and($context->canManageMembers())->toBeFalse()
        ->and($context->canManageAdmins())->toBeFalse()
        ->and($context->canInitiateModeTransition())->toBeFalse()
        ->and($context->isSameActorOrAdminOrOwner('owner-id'))->toBeFalse();
});

it('enforces the single Owner slot in the database', function (): void {
    User::query()->create(['name' => 'Owner One', 'email' => 'owner-one@example.test'])
        ->forceFill(['role' => UserRole::Owner->value])->save();

    expect(function (): void {
        User::query()->create(['name' => 'Owner Two', 'email' => 'owner-two@example.test'])
            ->forceFill(['role' => UserRole::Owner->value])->save();
    })->toThrow(QueryException::class);
});

it('detects a rogue host auth artifact with a positive control', function (): void {
    $thinHost = __DIR__.'/Fixtures/ThinHost';
    $rogueHost = __DIR__.'/Fixtures/RogueHost';
    $auth = config('auth');

    expect(ThinHostConformance::sourceArtifacts($thinHost))->toBe([])
        ->and(is_array($auth) ? ThinHostConformance::configurationArtifacts($auth) : ['missing-auth-config'])->toBe([])
        ->and(ThinHostConformance::sourceArtifacts($rogueHost))->toBe([
            'app/Models/User.php' => 'app-user-model',
        ]);
});
