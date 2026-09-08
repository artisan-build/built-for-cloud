<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\AuthorityState;
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
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
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

    $user->forceFill([
        'email' => 'changed@example.test',
        'role' => UserRole::Admin->value,
        'scalpels_issuer' => 'https://scalpels.example',
        'scalpels_connection_id' => 'stable-connection',
        'scalpels_id' => 'stable-subject',
    ])->save();

    expect($user->password)->toBeNull()
        ->and($user->refresh()->getKey())->toBe($stableId)
        ->and($user->status)->toBe('active')
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

    User::query()->create(['name' => 'Standalone One', 'email' => 'standalone-one@example.test']);
    User::query()->create(['name' => 'Standalone Two', 'email' => 'standalone-two@example.test']);

    $partialIdentities = [
        ['https://scalpels.example', null, null],
        [null, 'connection-partial', null],
        [null, null, 'subject-partial'],
        ['https://scalpels.example', 'connection-partial', null],
        ['https://scalpels.example', null, 'subject-partial'],
        [null, 'connection-partial', 'subject-partial'],
    ];

    foreach ($partialIdentities as $index => [$issuer, $connection, $subject]) {
        expect(fn (): bool => DB::table('users')->insert([
            'name' => 'Partial '.$index,
            'email' => 'partial-'.$index.'@example.test',
            'role' => UserRole::Member->value,
            'status' => 'active',
            'scalpels_issuer' => $issuer,
            'scalpels_connection_id' => $connection,
            'scalpels_id' => $subject,
            'email_is_generated' => false,
            'created_at' => now(),
            'updated_at' => now(),
        ]))->toThrow(QueryException::class);
    }
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

it('fails loudly for a conventional autoloadable App Models User conflict', function (): void {
    require_once __DIR__.'/Fixtures/RogueHost/app/Models/User.php';
    config()->set('auth.providers.users.model', App\Models\User::class);

    expect(fn () => (new BuiltForCloudServiceProvider(app()))->boot())
        ->toThrow(UnsupportedHumanAuthConfiguration::class, 'Conflicting provider');
});

it('fails loudly for a conflicting web guard', function (): void {
    config()->set('auth.guards.web', ['driver' => 'token', 'provider' => 'users']);

    expect(fn () => (new BuiltForCloudServiceProvider(app()))->boot())
        ->toThrow(UnsupportedHumanAuthConfiguration::class, 'Conflicting guard');
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

it('derives immutable opaque identity from the canonical user across recreated contexts', function (): void {
    $user = User::query()->create([
        'name' => 'Stable Context User',
        'email' => 'stable-context@example.test',
    ]);
    $authority = AuthorityState::fromRaw(AuthorityMode::Managed->value, 9);
    $first = DomainIdentityContext::forUser($user, $authority);

    $user->forceFill(['email' => 'changed-context@example.test'])->save();
    $recreated = DomainIdentityContext::forUser(User::query()->findOrFail($user->getKey()), $authority);
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
        ->and($first->credentialOwnership())->toBe(CredentialOwnership::Account)
        ->and($first->actorId())->toBe((string) $user->getKey())
        ->and($first->actorId())->not->toBe($user->email)
        ->and((new ReflectionMethod(DomainIdentityContext::class, 'forUser'))->getNumberOfParameters())->toBe(2);

    $constructorType = (new ReflectionClass(ReelProtectionDecision::class))
        ->getConstructor()?->getParameters()[0]->getType();

    expect((string) $constructorType)->toBe(IdentityContext::class)
        ->and(ContextContractScan::violations(IdentityContext::class))->toBe([])
        ->and(ContextContractScan::violations(RogueIdentityContext::class))->not->toBe([]);
});

it('stores one authority record and advances generation with compare and set', function (): void {
    expect(DB::table('bfc_authority')->count())->toBe(1)
        ->and(is_subclass_of(InstallationAuthority::class, Model::class))->toBeFalse();

    $initial = InstallationAuthority::current();
    $changed = InstallationAuthority::change($initial, AuthorityMode::Managed);

    expect($initial->mode)->toBe(AuthorityMode::Standalone)
        ->and($initial->generation)->toBe(1)
        ->and($changed?->mode)->toBe(AuthorityMode::Managed)
        ->and($changed?->generation)->toBe(2)
        ->and(InstallationAuthority::change($initial, AuthorityMode::Managed))->toBeNull()
        ->and(DB::table('bfc_authority')->count())->toBe(1);
});

it('rejects invalid authority expectations and reports a missing record as invalid', function (): void {
    expect(InstallationAuthority::change(
        AuthorityState::fromRaw('unexpected', 1),
        AuthorityMode::Managed,
    ))->toBeNull();

    config()->set('database.connections.authority_empty', [
        'driver' => 'sqlite',
        'database' => ':memory:',
        'prefix' => '',
    ]);

    Schema::connection('authority_empty')->create('bfc_authority', function ($table): void {
        $table->string('key')->primary();
        $table->string('mode');
        $table->unsignedBigInteger('generation');
    });

    $missing = InstallationAuthority::current('authority_empty');

    expect($missing->isValid())->toBeFalse()
        ->and($missing->mode)->toBeNull()
        ->and($missing->generation)->toBe(0);

    DB::purge('authority_empty');
});

it('structurally rejects invalid authority rows and non-monotonic writes', function (): void {
    expect(fn (): bool => DB::table('bfc_authority')->insert([
        'key' => 'another-installation',
        'mode' => AuthorityMode::Standalone->value,
        'generation' => 1,
    ]))->toThrow(QueryException::class);

    expect(fn (): int => DB::table('bfc_authority')->update([
        'mode' => AuthorityMode::Managed->value,
    ]))->toThrow(QueryException::class);

    expect(fn (): int => DB::table('bfc_authority')->update([
        'generation' => 0,
    ]))->toThrow(QueryException::class);

    $changed = InstallationAuthority::change(InstallationAuthority::current(), AuthorityMode::Managed);

    expect($changed?->generation)->toBe(2);

    expect(fn (): int => DB::table('bfc_authority')->update([
        'generation' => 1,
    ]))->toThrow(QueryException::class);

    expect(fn (): int => DB::table('bfc_authority')->update([
        'mode' => 'unexpected',
        'generation' => 3,
    ]))->toThrow(QueryException::class);

    expect(fn (): int => DB::table('bfc_authority')->delete())
        ->toThrow(QueryException::class);

    expect(InstallationAuthority::current()->mode)->toBe(AuthorityMode::Managed)
        ->and(InstallationAuthority::current()->generation)->toBe(2)
        ->and(DB::table('bfc_authority')->count())->toBe(1);
});

it('returns the authority state written before a later writer advances it', function (): void {
    $advanced = false;

    DB::listen(function ($query) use (&$advanced): void {
        if ($advanced || ! str_starts_with(strtolower($query->sql), 'update "bfc_authority"')) {
            return;
        }

        $advanced = true;
        InstallationAuthority::change(
            AuthorityState::fromRaw(AuthorityMode::Managed->value, 2),
            AuthorityMode::Standalone,
        );
    });

    $written = InstallationAuthority::change(
        InstallationAuthority::current(),
        AuthorityMode::Managed,
    );

    expect($advanced)->toBeTrue()
        ->and($written?->mode)->toBe(AuthorityMode::Managed)
        ->and($written?->generation)->toBe(2)
        ->and(InstallationAuthority::current()->mode)->toBe(AuthorityMode::Standalone)
        ->and(InstallationAuthority::current()->generation)->toBe(3);
});

it('denies every context decision for unknown authority mode', function (): void {
    $context = new DomainIdentityContext(
        'owner-id',
        UserRole::Owner,
        'unexpected',
        1,
        CredentialOwnership::Account,
    );

    expect($context->authorityMode())->toBeNull()
        ->and($context->canUseProduct())->toBeFalse()
        ->and($context->canManageMembers())->toBeFalse()
        ->and($context->canManageAdmins())->toBeFalse()
        ->and($context->canInitiateModeTransition())->toBeFalse()
        ->and($context->isSameActorOrAdminOrOwner('owner-id'))->toBeFalse();
});

it('denies human role authority to installation-owned credentials', function (): void {
    $context = new DomainIdentityContext(
        'installation-credential',
        UserRole::Owner,
        AuthorityMode::Managed,
        1,
        CredentialOwnership::Installation,
    );

    expect($context->canUseProduct())->toBeFalse()
        ->and($context->canManageMembers())->toBeFalse()
        ->and($context->canManageAdmins())->toBeFalse()
        ->and($context->canInitiateModeTransition())->toBeFalse()
        ->and($context->isSameActorOrAdminOrOwner('installation-credential'))->toBeFalse();
});

it('enforces the single Owner slot in the database', function (): void {
    $first = User::query()->create(['name' => 'Owner One', 'email' => 'owner-one@example.test']);
    $second = User::query()->create(['name' => 'Owner Two', 'email' => 'owner-two@example.test']);

    expect(fn (): int => User::query()->whereKey([$first->getKey(), $second->getKey()])->update([
        'role' => UserRole::Owner->value,
    ]))->toThrow(QueryException::class);

    expect(User::query()->where('role', UserRole::Owner->value)->count())->toBe(0);

    DB::table('users')->where('id', $first->getKey())->update(['role' => UserRole::Owner->value]);

    expect(fn (): int => DB::table('users')->where('id', $second->getKey())->update([
        'role' => UserRole::Owner->value,
    ]))->toThrow(QueryException::class);

    User::query()->create(['name' => 'Admin One', 'email' => 'admin-one@example.test'])
        ->forceFill(['role' => UserRole::Admin->value])->save();
    User::query()->create(['name' => 'Admin Two', 'email' => 'admin-two@example.test'])
        ->forceFill(['role' => UserRole::Admin->value])->save();
    User::query()->create(['name' => 'Member Three', 'email' => 'member-three@example.test']);

    expect(User::query()->where('role', UserRole::Owner->value)->count())->toBe(1)
        ->and(User::query()->where('role', UserRole::Admin->value)->count())->toBe(2)
        ->and(User::query()->where('role', UserRole::Member->value)->count())->toBe(2);
});

it('detects a rogue host auth artifact with a positive control', function (): void {
    $thinHost = __DIR__.'/Fixtures/ThinHost';
    $rogueHost = __DIR__.'/Fixtures/RogueHost';
    $auth = config('auth');

    expect(ThinHostConformance::sourceArtifacts($thinHost))->toBe([])
        ->and(is_array($auth) ? ThinHostConformance::configurationArtifacts($auth) : ['missing-auth-config'])->toBe([])
        ->and(ThinHostConformance::sourceArtifacts($rogueHost))->toBe([
            'app/Console/Commands/IssueToken.php' => 'token-command',
            'app/Http/Controllers/Auth/LoginController.php' => 'auth-controller',
            'app/Models/User.php' => 'app-user-model',
            'database/migrations/2026_09_08_000000_create_users_table.php' => 'users-migration',
            'resources/views/auth/login.blade.php' => 'copied-auth-ui',
        ])
        ->and(ThinHostConformance::configurationArtifacts([
            'defaults' => ['guard' => 'rogue'],
            'guards' => ['rogue' => ['driver' => 'token', 'provider' => 'rogue']],
            'providers' => ['users' => ['driver' => 'database', 'table' => 'users']],
        ]))->toBe([
            'human-provider',
            'human-guard',
            'custom-guard:rogue',
        ]);
});
