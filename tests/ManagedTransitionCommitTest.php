<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Auth\CredentialResolver;
use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\Exceptions\ManagedAuthRefused;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageTransitions;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\Invitation;
use ArtisanBuild\BuiltForCloud\ManagedAuthConfirmation;
use ArtisanBuild\BuiltForCloud\ManagedAuthConnection;
use ArtisanBuild\BuiltForCloud\ManagedAuthExchange;
use ArtisanBuild\BuiltForCloud\ManagedMembershipResponses;
use ArtisanBuild\BuiltForCloud\ManagedTransition;
use ArtisanBuild\BuiltForCloud\ManagedTransitionDirection;
use ArtisanBuild\BuiltForCloud\ManagedTransitions;
use ArtisanBuild\BuiltForCloud\ManagedTransitionStatus;
use ArtisanBuild\BuiltForCloud\StandaloneAccess;
use ArtisanBuild\BuiltForCloud\StandaloneHandoff;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\ManagedTransitionAuthorityFixture;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Cookie;

uses(RefreshDatabase::class);

/**
 * @param  list<array<string, mixed>>  $roster
 * @return array{User, ManagedTransitionAuthorityFixture}
 */
function p4dConfigure(ManagedTransitionDirection $direction, array $roster, int $generation = 7): array
{
    DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
        'mode' => $direction->modeBefore()->value,
        'generation' => $generation,
        'issuer' => 'https://issuer.example.test',
        'connection_id' => 'transition-connection',
        'organization_id' => 'transition-organization',
        'installation_id' => 'transition-installation',
        'authority_base_url' => 'https://transition-authority.example.test',
        'managed_connection_status' => 'active',
        'managed_connection_generation' => $generation,
        'managed_connection_roster_version' => 40,
        'managed_connection_response_sequence' => 70,
        'managed_ownership_generation' => $generation,
        'managed_ownership_roster_version' => 40,
        'managed_ownership_response_sequence' => 70,
    ]);
    config([
        'built-for-cloud.managed.client_secret' => 'transition-secret',
        'built-for-cloud.managed.ca_bundle' => null,
        'session.driver' => 'database',
        'session.table' => 'sessions',
    ]);
    $owner = User::query()->create([
        'name' => 'P4d Owner',
        'email' => 'p4d-owner@example.test',
        'password' => $direction === ManagedTransitionDirection::Exit ? null : Hash::make('owner-password'),
    ]);
    $owner->forceFill([
        'role' => 'owner',
        'status' => 'active',
        'email_verified_at' => now(),
        'membership_confirmed_at' => now(),
        'membership_checked_at' => now(),
        'membership_response_at' => now(),
        'managed_membership_status' => $direction === ManagedTransitionDirection::Exit ? 'active' : null,
        'managed_membership_role' => $direction === ManagedTransitionDirection::Exit ? 'owner' : null,
        'managed_membership_generation' => $direction === ManagedTransitionDirection::Exit ? $generation : null,
        'managed_membership_roster_version' => $direction === ManagedTransitionDirection::Exit ? 40 : null,
        'managed_membership_response_sequence' => $direction === ManagedTransitionDirection::Exit ? 70 : null,
        'managed_membership_responded_at' => $direction === ManagedTransitionDirection::Exit ? now()->toRfc3339String() : null,
        'remember_token' => 'owner-remember-token',
        ...($direction === ManagedTransitionDirection::Exit ? [
            'scalpels_issuer' => 'https://issuer.example.test',
            'scalpels_connection_id' => 'transition-connection',
            'scalpels_id' => 'owner-subject',
            'original_contact_email' => 'standalone-owner@example.test',
        ] : []),
    ])->save();
    $fixture = new ManagedTransitionAuthorityFixture(generation: $generation);
    $fixture->rosterPages = ['NULL' => $roster];
    Http::fake(fn (ClientRequest $request): mixed => $fixture->respond($request));

    return [$owner->refresh(), $fixture];
}

/** @param list<array<string, mixed>> $mapping */
function p4dProposed(User $owner, ManagedTransitionDirection $direction, array $mapping): ManagedTransition
{
    $transitions = app(ManagedTransitions::class);
    $transition = $transitions->prepare($owner, $direction);
    $transition = $transitions->fetchRoster($transition);

    return $transitions->propose($transition, $mapping);
}

function p4dInvitation(string $email, string $role = 'member'): Invitation
{
    return Invitation::factory()->create([
        'email' => $email,
        'role' => $role,
        'expires_at' => now()->addYears(20),
    ]);
}

/** @return array<string, list<array<string, mixed>>> */
function p4dStateExceptAttempt(): array
{
    $tables = [
        'users',
        'bfc_authority',
        'bfc_managed_transition_roster_members',
        'bfc_managed_transition_roster_cursors',
        'bfc_managed_transition_mappings',
        'invitations',
        'sessions',
        'password_reset_tokens',
        'credentials',
        'bfc_managed_handoffs',
        'api_tokens',
        'bfc_delegated_actors',
        'integration_entitlements',
        'integration_events',
    ];

    return collect($tables)->mapWithKeys(static fn (string $table): array => [
        $table => DB::table($table)->orderBy(DB::raw('1'))->get()->map(
            static fn (object $row): array => (array) $row,
        )->all(),
    ])->all();
}

/** @return array{ManagedTransition, User, User, Invitation, ManagedTransitionAuthorityFixture} */
function p4dCompletedExit(): array
{
    $roster = [
        [
            'scalpels_id' => 'owner-subject',
            'membership_status' => 'active',
            'role' => 'owner',
            'display_name' => 'Exit Owner',
            'contact_email' => 'standalone-owner@example.test',
            'contact_email_verified' => true,
        ],
        [
            'scalpels_id' => 'invited-subject',
            'membership_status' => 'active',
            'role' => 'member',
            'display_name' => 'Invited Subject',
            'contact_email' => 'invited-exit@example.test',
            'contact_email_verified' => true,
        ],
    ];
    [$owner, $fixture] = p4dConfigure(ManagedTransitionDirection::Exit, $roster);
    $retained = User::query()->create(['name' => 'Retained Generated', 'email' => 'retained+bfc@example.test']);
    $retained->forceFill([
        'role' => 'admin',
        'status' => 'active',
        'email_verified_at' => now(),
        'email_is_generated' => true,
        'membership_confirmed_at' => now(),
        'membership_checked_at' => now(),
        'membership_response_at' => now(),
        'managed_membership_status' => 'active',
        'managed_membership_role' => 'admin',
        'managed_membership_generation' => 7,
        'managed_membership_roster_version' => 40,
        'managed_membership_response_sequence' => 70,
        'managed_membership_responded_at' => now()->toRfc3339String(),
        'remember_token' => 'retained-remember-token',
    ])->save();
    $excluded = User::query()->create(['name' => 'Excluded Exit', 'email' => 'excluded-exit@example.test']);
    $excluded->forceFill([
        'role' => 'member',
        'status' => 'active',
        'membership_confirmed_at' => now(),
        'membership_checked_at' => now(),
        'membership_response_at' => now(),
        'managed_membership_status' => 'active',
        'managed_membership_role' => 'member',
        'managed_membership_generation' => 7,
        'managed_membership_roster_version' => 40,
        'managed_membership_response_sequence' => 70,
        'managed_membership_responded_at' => now()->toRfc3339String(),
        'remember_token' => 'excluded-remember-token',
    ])->save();
    $linked = p4dInvitation('invited-exit@example.test', 'admin');
    $kept = p4dInvitation('kept-invitation@example.test', 'admin');
    $cancelled = p4dInvitation('cancelled-invitation@example.test');
    foreach ([$owner, $retained, $excluded] as $index => $user) {
        DB::table('sessions')->insert([
            'id' => 'exit-session-'.$index, 'user_id' => $user->getKey(), 'payload' => 'exit-'.$index, 'last_activity' => 1,
        ]);
        Credential::factory()->forUser((string) $user->getKey())->create(['name' => 'exit-account-'.$index]);
    }
    DB::table('password_reset_tokens')->insert([
        'email' => $excluded->email, 'token' => hash('sha256', 'exit-reset'), 'created_at' => now(),
    ]);
    Credential::factory()->create([
        'subject_type' => SubjectType::Installation,
        'subject_ref' => 'transition-installation',
        'name' => 'exit-deployment-survives',
    ]);
    DB::table('bfc_managed_handoffs')->insert([
        'state_hash' => hash('sha256', 'exit-state'),
        'session_nonce_hash' => hash('sha256', 'exit-nonce'),
        'issuer' => 'https://issuer.example.test',
        'connection_id' => 'transition-connection',
        'organization_id' => 'transition-organization',
        'installation_id' => 'transition-installation',
        'authority_generation' => 7,
        'expires_at' => now()->addHour(),
        'created_at' => now(),
        'updated_at' => now(),
    ]);
    $mapping = [
        [
            'scalpels_id' => 'owner-subject', 'local_kind' => 'user', 'local_id' => (string) $owner->getKey(),
            'role' => 'owner', 'disposition' => 'link', 'final_email' => 'standalone-owner@example.test',
        ],
        [
            'scalpels_id' => null, 'local_kind' => 'user', 'local_id' => (string) $retained->getKey(),
            'role' => 'admin', 'disposition' => 'retain_local', 'final_email' => $retained->email,
        ],
        [
            'scalpels_id' => null, 'local_kind' => 'user', 'local_id' => (string) $excluded->getKey(),
            'role' => null, 'disposition' => 'exclude', 'final_email' => null,
        ],
        [
            'scalpels_id' => 'invited-subject', 'local_kind' => 'invitation', 'local_id' => $linked->id,
            'role' => 'member', 'disposition' => 'link', 'final_email' => 'invited-exit@example.test',
        ],
        [
            'scalpels_id' => null, 'local_kind' => 'invitation', 'local_id' => $kept->id,
            'role' => null, 'disposition' => 'retain_local', 'final_email' => null,
        ],
        [
            'scalpels_id' => null, 'local_kind' => 'invitation', 'local_id' => $cancelled->id,
            'role' => null, 'disposition' => 'exclude', 'final_email' => null,
        ],
    ];
    $transition = p4dProposed($owner, ManagedTransitionDirection::Exit, $mapping);
    $transition = app(ManagedTransitions::class)->complete($owner, $transition);

    return [$transition, $owner->refresh(), $retained->refresh(), $kept->refresh(), $fixture];
}

it('atomically applies every adoption disposition and invalidates local authority for every identity', function (): void {
    $roster = [
        [
            'scalpels_id' => 'owner-subject', 'membership_status' => 'active', 'role' => 'owner',
            'display_name' => 'Managed Owner', 'contact_email' => 'managed-owner@example.test', 'contact_email_verified' => true,
        ],
        [
            'scalpels_id' => 'invited-subject', 'membership_status' => 'active', 'role' => 'admin',
            'display_name' => 'Managed Invite', 'contact_email' => 'managed-invite@example.test', 'contact_email_verified' => true,
        ],
        [
            'scalpels_id' => 'created-subject', 'membership_status' => 'active', 'role' => 'member',
            'display_name' => 'Managed Create', 'contact_email' => 'managed-create@example.test', 'contact_email_verified' => true,
        ],
        [
            'scalpels_id' => 'deferred-subject', 'membership_status' => 'active', 'role' => 'member',
            'display_name' => 'Managed Deferred', 'contact_email' => 'managed-deferred@example.test', 'contact_email_verified' => true,
        ],
    ];
    [$owner, $fixture] = p4dConfigure(ManagedTransitionDirection::Adopt, $roster);
    $excluded = User::query()->create(['name' => 'Excluded Local', 'email' => 'excluded-local@example.test', 'password' => Hash::make('old')]);
    $excluded->forceFill([
        'role' => 'member',
        'status' => 'active',
        'original_contact_email' => 'historical@example.test',
        'remember_token' => 'excluded-adoption-remember-token',
    ])->save();
    $excludedId = (string) $excluded->getKey();
    $linkedInvitation = p4dInvitation('old-invite@example.test', 'member');
    $excludedInvitation = p4dInvitation('excluded-invite@example.test');
    $staleSecrets = [];
    foreach ([$owner, $excluded] as $index => $user) {
        DB::table('sessions')->insert([
            'id' => 'adopt-session-'.$index, 'user_id' => $user->getKey(), 'payload' => 'session-'.$index, 'last_activity' => 1,
        ]);
        DB::table('password_reset_tokens')->insert([
            'email' => $user->email, 'token' => hash('sha256', 'reset-'.$index), 'created_at' => now(),
        ]);
        $staleSecrets[] = $secret = 'adopt-account-secret-'.$index;
        $credential = Credential::factory()->forUser((string) $user->getKey())->create([
            'name' => 'account-'.$index,
            'secret_hash' => hash('sha256', $secret),
        ]);
        if ($user->is($excluded)) {
            $excludedCredential = $credential;
        }
    }
    $deployment = Credential::factory()->create([
        'subject_type' => SubjectType::Installation,
        'subject_ref' => 'transition-installation',
        'name' => 'deployment-survives',
    ]);
    DB::table('bfc_managed_handoffs')->insert([
        'state_hash' => hash('sha256', 'state'),
        'session_nonce_hash' => hash('sha256', 'nonce'),
        'issuer' => 'https://issuer.example.test',
        'connection_id' => 'transition-connection',
        'organization_id' => 'transition-organization',
        'installation_id' => 'transition-installation',
        'authority_generation' => 6,
        'expires_at' => now()->addHour(),
        'created_at' => now(),
        'updated_at' => now(),
    ]);
    $mapping = [
        [
            'scalpels_id' => 'owner-subject', 'local_kind' => 'user', 'local_id' => (string) $owner->getKey(),
            'role' => 'owner', 'disposition' => 'link', 'final_email' => 'managed-owner@example.test',
        ],
        [
            'scalpels_id' => 'invited-subject', 'local_kind' => 'invitation', 'local_id' => $linkedInvitation->id,
            'role' => 'admin', 'disposition' => 'link', 'final_email' => 'managed-invite@example.test',
        ],
        [
            'scalpels_id' => 'created-subject', 'local_kind' => null, 'local_id' => null,
            'role' => 'member', 'disposition' => 'create', 'final_email' => 'managed-create@example.test',
        ],
        [
            'scalpels_id' => 'deferred-subject', 'local_kind' => null, 'local_id' => null,
            'role' => null, 'disposition' => 'defer_to_managed_jit', 'final_email' => null,
        ],
        [
            'scalpels_id' => null, 'local_kind' => 'user', 'local_id' => (string) $excluded->getKey(),
            'role' => null, 'disposition' => 'exclude', 'final_email' => null,
        ],
        [
            'scalpels_id' => null, 'local_kind' => 'invitation', 'local_id' => $excludedInvitation->id,
            'role' => null, 'disposition' => 'exclude', 'final_email' => null,
        ],
    ];

    $this->actingAsVersioned($owner);
    $completed = app(ManagedTransitions::class)->complete(
        $owner,
        p4dProposed($owner, ManagedTransitionDirection::Adopt, $mapping),
    );
    $authority = InstallationAuthority::current();
    $linkedOwner = $owner->refresh();
    $excluded = $excluded->refresh();
    $claimed = User::query()->where('scalpels_id', 'invited-subject')->sole();
    $created = User::query()->where('scalpels_id', 'created-subject')->sole();

    expect($completed->status)->toBe(ManagedTransitionStatus::Acknowledged)
        ->and($authority->mode)->toBe(AuthorityMode::Managed)
        ->and($authority->generation)->toBe(8)
        ->and((string) $linkedOwner->getKey())->toBe((string) $owner->getKey())
        ->and($linkedOwner->email)->toBe('managed-owner@example.test')
        ->and($linkedOwner->scalpels_id)->toBe('owner-subject')
        ->and($linkedOwner->password)->toBeNull()
        ->and($linkedOwner->auth_session_version)->toBe(2)
        ->and($linkedOwner->remember_token)->toBeNull()
        ->and($excluded->status)->toBe('inactive')
        ->and($excluded->auth_session_version)->toBe(2)
        ->and($excluded->remember_token)->toBeNull()
        ->and($excluded->original_contact_email)->toBe('historical@example.test')
        ->and((string) $excluded->getKey())->toBe($excludedId)
        ->and((string) $excludedCredential->refresh()->user_id)->toBe($excludedId)
        ->and($excludedCredential->revoked_at)->not->toBeNull()
        ->and($claimed->role)->toBe('admin')
        ->and($claimed->email)->toBe('managed-invite@example.test')
        ->and($created->email)->toBe('managed-create@example.test')
        ->and(User::query()->where('scalpels_id', 'deferred-subject')->exists())->toBeFalse()
        ->and($linkedInvitation->refresh()->accepted_at)->not->toBeNull()
        ->and($linkedInvitation->refresh()->used_by)->toBe((string) $claimed->getKey())
        ->and($excludedInvitation->refresh()->cancelled_at)->not->toBeNull()
        ->and(DB::table('sessions')->count())->toBe(0)
        ->and(DB::table('password_reset_tokens')->count())->toBe(0)
        ->and(Credential::query()->whereNotNull('user_id')->whereNull('revoked_at')->count())->toBe(0)
        ->and($deployment->refresh()->revoked_at)->toBeNull()
        ->and(DB::table('bfc_managed_handoffs')->whereNull('consumed_at')->count())->toBe(0)
        ->and(array_column($fixture->calls, 'leg'))->toBe(['T1', 'T2', 'T3', 'T4']);

    foreach ($staleSecrets as $secret) {
        expect(app(CredentialResolver::class)->resolve(CredentialKind::Bearer, $secret))->toBeNull();
    }
    $this->get(route('bfc.members.index', absolute: false))->assertNotFound();
});

it('rejects an invalid exact-generation tuple before any protected effect', function (): void {
    $roster = [[
        'scalpels_id' => 'owner-subject', 'membership_status' => 'active', 'role' => 'owner',
        'display_name' => 'Rollback Owner', 'contact_email' => 'rollback-owner@example.test', 'contact_email_verified' => true,
    ]];
    [$owner] = p4dConfigure(ManagedTransitionDirection::Adopt, $roster);
    $invitation = p4dInvitation('rollback-invitation@example.test');
    Credential::factory()->forUser((string) $owner->getKey())->create();
    DB::table('sessions')->insert(['id' => 'rollback-session', 'user_id' => $owner->getKey(), 'payload' => 'before', 'last_activity' => 1]);
    DB::table('password_reset_tokens')->insert([
        'email' => $owner->email, 'token' => hash('sha256', 'rollback'), 'created_at' => now(),
    ]);
    $transition = p4dProposed($owner, ManagedTransitionDirection::Adopt, [
        [
            'scalpels_id' => 'owner-subject', 'local_kind' => 'user', 'local_id' => (string) $owner->getKey(),
            'role' => 'owner', 'disposition' => 'link', 'final_email' => 'rollback-owner@example.test',
        ],
        [
            'scalpels_id' => null, 'local_kind' => 'invitation', 'local_id' => $invitation->id,
            'role' => null, 'disposition' => 'exclude', 'final_email' => null,
        ],
    ]);
    $transition = app(ManagedTransitions::class)->stage($transition);
    $transition->forceFill(['generation_after' => 9])->save();
    $before = p4dStateExceptAttempt();

    expect(fn () => app(ManagedTransitions::class)->commit($transition->refresh(), $owner))
        ->toThrow(ManagedAuthRefused::class)
        ->and(p4dStateExceptAttempt())->toBe($before)
        ->and($transition->refresh()->status)->toBe(ManagedTransitionStatus::Staged)
        ->and($transition->refresh()->local_commit_receipt)->toBeNull();
});

it('rolls back every protected store when the post-change authority check fails', function (): void {
    $roster = [[
        'scalpels_id' => 'owner-subject', 'membership_status' => 'active', 'role' => 'owner',
        'display_name' => 'Post-change Owner', 'contact_email' => 'post-change-owner@example.test', 'contact_email_verified' => true,
    ]];
    [$owner] = p4dConfigure(ManagedTransitionDirection::Adopt, $roster);
    Credential::factory()->forUser((string) $owner->getKey())->create();
    DB::table('sessions')->insert([
        'id' => 'post-change-session', 'user_id' => $owner->getKey(), 'payload' => 'before', 'last_activity' => 1,
    ]);
    $transition = p4dProposed($owner, ManagedTransitionDirection::Adopt, [[
        'scalpels_id' => 'owner-subject', 'local_kind' => 'user', 'local_id' => (string) $owner->getKey(),
        'role' => 'owner', 'disposition' => 'link', 'final_email' => 'post-change-owner@example.test',
    ]]);
    $transition = app(ManagedTransitions::class)->stage($transition);
    DB::unprepared(<<<'SQL'
        CREATE TRIGGER p4d_post_mode_change
        AFTER UPDATE OF mode ON bfc_authority
        BEGIN
            UPDATE bfc_authority SET installation_id = 'post-change-mismatch' WHERE key = NEW.key;
        END
        SQL);
    $before = p4dStateExceptAttempt();

    expect(fn () => app(ManagedTransitions::class)->commit($transition, $owner))
        ->toThrow(ManagedAuthRefused::class, 'transition_state_conflict')
        ->and(p4dStateExceptAttempt())->toBe($before)
        ->and($transition->refresh()->status)->toBe(ManagedTransitionStatus::Staged)
        ->and($transition->local_commit_receipt)->toBeNull();
});

it('deletes mode-switch sessions from a distinct configured session connection', function (): void {
    $roster = [[
        'scalpels_id' => 'owner-subject', 'membership_status' => 'active', 'role' => 'owner',
        'display_name' => 'Remote Session Owner', 'contact_email' => 'remote-session-owner@example.test', 'contact_email_verified' => true,
    ]];
    [$owner] = p4dConfigure(ManagedTransitionDirection::Adopt, $roster);
    config([
        'database.connections.transition_sessions' => [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
            'foreign_key_constraints' => true,
        ],
        'session.connection' => 'transition_sessions',
    ]);
    Schema::connection('transition_sessions')->create('sessions', static function (Blueprint $table): void {
        $table->string('id')->primary();
        $table->foreignId('user_id')->nullable()->index();
        $table->text('payload');
        $table->integer('last_activity')->index();
    });
    DB::connection('transition_sessions')->table('sessions')->insert([
        'id' => 'remote-session', 'user_id' => $owner->getKey(), 'payload' => 'remote', 'last_activity' => 1,
    ]);
    DB::table('sessions')->insert([
        'id' => 'default-session', 'user_id' => $owner->getKey(), 'payload' => 'default', 'last_activity' => 1,
    ]);

    app(ManagedTransitions::class)->complete(
        $owner,
        p4dProposed($owner, ManagedTransitionDirection::Adopt, [[
            'scalpels_id' => 'owner-subject', 'local_kind' => 'user', 'local_id' => (string) $owner->getKey(),
            'role' => 'owner', 'disposition' => 'link', 'final_email' => 'remote-session-owner@example.test',
        ]]),
    );

    expect(DB::table('sessions')->count())->toBe(0)
        ->and(DB::connection('transition_sessions')->table('sessions')->count())->toBe(0)
        ->and($owner->refresh()->auth_session_version)->toBe(2);
});

it('revalidates final email uniqueness immediately before commit with zero protected effects', function (): void {
    $roster = [[
        'scalpels_id' => 'owner-subject', 'membership_status' => 'active', 'role' => 'owner',
        'display_name' => 'Unique Owner', 'contact_email' => 'unique-owner@example.test', 'contact_email_verified' => true,
    ]];
    [$owner] = p4dConfigure(ManagedTransitionDirection::Adopt, $roster);
    $excluded = User::query()->create(['name' => 'Late Collision', 'email' => 'before-collision@example.test']);
    $excluded->forceFill(['role' => 'member', 'status' => 'active'])->save();
    $transition = p4dProposed($owner, ManagedTransitionDirection::Adopt, [
        [
            'scalpels_id' => 'owner-subject', 'local_kind' => 'user', 'local_id' => (string) $owner->getKey(),
            'role' => 'owner', 'disposition' => 'link', 'final_email' => 'unique-owner@example.test',
        ],
        [
            'scalpels_id' => null, 'local_kind' => 'user', 'local_id' => (string) $excluded->getKey(),
            'role' => null, 'disposition' => 'exclude', 'final_email' => null,
        ],
    ]);
    $transition = app(ManagedTransitions::class)->stage($transition);
    DB::table('bfc_managed_transition_mappings')
        ->where('managed_transition_id', $transition->id)
        ->where('scalpels_id', 'owner-subject')
        ->update(['final_email' => $excluded->email]);
    $stagePayload = json_decode($transition->stage_request_body, true, flags: JSON_THROW_ON_ERROR);
    $stagePayload['mapping'] = p4dStoredMapping($transition);
    $stageBody = json_encode($stagePayload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    $transition->forceFill([
        'stage_request_body' => $stageBody,
        'stage_body_digest' => hash('sha256', $stageBody),
    ])->save();
    $before = p4dStateExceptAttempt();

    expect(fn () => app(ManagedTransitions::class)->commit($transition->refresh(), $owner))
        ->toThrow(ManagedAuthRefused::class)
        ->and(p4dStateExceptAttempt())->toBe($before)
        ->and($transition->refresh()->status)->toBe(ManagedTransitionStatus::Staged);
});

it('relies on the database trigger to reject a mode change without a generation advance', function (): void {
    expect(fn () => DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
        'mode' => AuthorityMode::Managed->value,
    ]))->toThrow(QueryException::class)
        ->and(InstallationAuthority::current()->mode)->toBe(AuthorityMode::Standalone)
        ->and(InstallationAuthority::current()->generation)->toBe(1);
});

it('refuses both wrong-direction same-mode commits before protected effects', function (ManagedTransitionDirection $startingDirection): void {
    $roster = [[
        'scalpels_id' => 'owner-subject', 'membership_status' => 'active', 'role' => 'owner',
        'display_name' => 'Direction Owner', 'contact_email' => 'p4d-owner@example.test', 'contact_email_verified' => true,
    ]];
    [$owner] = p4dConfigure($startingDirection, $roster);
    $transition = p4dProposed($owner, $startingDirection, [[
        'scalpels_id' => 'owner-subject', 'local_kind' => 'user', 'local_id' => (string) $owner->getKey(),
        'role' => 'owner', 'disposition' => 'link', 'final_email' => 'p4d-owner@example.test',
    ]]);
    $transition = app(ManagedTransitions::class)->stage($transition);
    $wrongDirection = $startingDirection === ManagedTransitionDirection::Adopt
        ? ManagedTransitionDirection::Exit
        : ManagedTransitionDirection::Adopt;
    $sameMode = $startingDirection->modeBefore()->value;
    $transition->forceFill([
        'direction' => $wrongDirection,
        'mode_before' => $sameMode,
        'mode_after' => $sameMode,
    ])->save();
    $before = p4dStateExceptAttempt();
    $transitionBefore = $transition->refresh()->getAttributes();

    expect(fn () => app(ManagedTransitions::class)->commit($transition->refresh(), $owner))
        ->toThrow(ManagedAuthRefused::class, 'transition_state_conflict')
        ->and(p4dStateExceptAttempt())->toBe($before)
        ->and($transition->refresh()->getAttributes())->toBe($transitionBefore);
})->with([ManagedTransitionDirection::Adopt, ManagedTransitionDirection::Exit]);

it('establishes an accessible standalone Owner and applies every exit disposition and invalidation', function (): void {
    [$transition, $owner, $retained, $kept] = p4dCompletedExit();
    $created = User::query()->where('scalpels_id', 'invited-subject')->sole();

    $authorityFreshness = DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->first([
        'managed_connection_status',
        'managed_connection_generation',
        'managed_connection_roster_version',
        'managed_connection_response_sequence',
        'managed_ownership_generation',
        'managed_ownership_roster_version',
        'managed_ownership_response_sequence',
    ]);
    $clearedUserFields = [
        'remember_token',
        'membership_confirmed_at',
        'membership_checked_at',
        'membership_response_at',
        'managed_membership_status',
        'managed_membership_role',
        'managed_membership_generation',
        'managed_membership_roster_version',
        'managed_membership_response_sequence',
        'managed_membership_responded_at',
    ];
    $excluded = User::query()->where('email', 'excluded-exit@example.test')->sole();

    expect($transition->status)->toBe(ManagedTransitionStatus::Acknowledged)
        ->and(InstallationAuthority::current()->mode)->toBe(AuthorityMode::Standalone)
        ->and(InstallationAuthority::current()->generation)->toBe(8)
        ->and($owner->email)->toBe('standalone-owner@example.test')
        ->and($owner->role)->toBe('owner')
        ->and($owner->password)->toBeNull()
        ->and($owner->email_verified_at)->not->toBeNull()
        ->and(StandaloneAccess::userCanReceiveRecovery($owner))->toBeTrue()
        ->and($retained->status)->toBe('active')
        ->and($retained->email_is_generated)->toBeTrue()
        ->and(StandaloneAccess::userCanReceiveRecovery($retained))->toBeFalse()
        ->and($created->role)->toBe('member')
        ->and($created->email_verified_at)->not->toBeNull()
        ->and($kept->email)->toBe('kept-invitation@example.test')
        ->and($kept->role)->toBe('admin')
        ->and($kept->accepted_at)->toBeNull()
        ->and($kept->cancelled_at)->toBeNull()
        ->and($excluded->status)->toBe('inactive')
        ->and(Invitation::query()->where('email', 'cancelled-invitation@example.test')->sole()->cancelled_at)->not->toBeNull()
        ->and(DB::table('sessions')->count())->toBe(0)
        ->and(DB::table('password_reset_tokens')->count())->toBe(0)
        ->and(Credential::query()->whereNotNull('user_id')->whereNull('revoked_at')->count())->toBe(0)
        ->and(Credential::query()->where('name', 'exit-deployment-survives')->value('revoked_at'))->toBeNull()
        ->and((array) $authorityFreshness)->toBe(array_fill_keys([
            'managed_connection_status',
            'managed_connection_generation',
            'managed_connection_roster_version',
            'managed_connection_response_sequence',
            'managed_ownership_generation',
            'managed_ownership_roster_version',
            'managed_ownership_response_sequence',
        ], null))
        ->and(DB::table('bfc_managed_handoffs')->whereNull('consumed_at')->count())->toBe(0);

    foreach ([$owner, $retained, $excluded] as $invalidated) {
        $invalidated = $invalidated->refresh();
        expect($invalidated->auth_session_version)->toBe(2)
            ->and($invalidated->only($clearedUserFields))->toBe(array_fill_keys($clearedUserFields, null));
    }

    auth()->logout();
    $token = bin2hex(random_bytes(32));
    DB::table('password_reset_tokens')->insert([
        'email' => $owner->email,
        'token' => hash('sha256', $token),
        'created_at' => now(),
    ]);
    $handoff = $this->get(route('bfc.password.reset', ['token' => $token], false));
    $handoff->assertRedirect(route('bfc.password.reset.form'));
    $cookie = $handoff->getCookie(StandaloneHandoff::COOKIE);
    expect($cookie)->toBeInstanceOf(Cookie::class);
    $this->withCookie(StandaloneHandoff::COOKIE, $cookie->getValue());
    $this->get(route('bfc.password.reset.form', absolute: false))
        ->assertOk()
        ->assertSee($owner->email);
    $this->post(route('bfc.password.update', absolute: false), [
        'token' => $token,
        'email' => $owner->email,
        'password' => 'new-owner-password',
        'password_confirmation' => 'new-owner-password',
    ])->assertRedirect(route('bfc.login'));
    $this->post(route('bfc.login.store', absolute: false), [
        'email' => 'standalone-owner@example.test',
        'password' => 'new-owner-password',
    ])->assertRedirect();
    $this->get(route('bfc.members.index', absolute: false))->assertOk();
});

it('rejects a pre-commit session re-persisted after exit commit on its next authenticated request', function (): void {
    $roster = [[
        'scalpels_id' => 'owner-subject', 'membership_status' => 'active', 'role' => 'owner',
        'display_name' => 'Residual Session Owner', 'contact_email' => 'residual-owner@example.test', 'contact_email_verified' => true,
    ]];
    [$owner, $fixture] = p4dConfigure(ManagedTransitionDirection::Exit, $roster);
    Route::middleware('web')->get('/_bfc-test/pre-commit-session', function () use ($owner): string {
        Auth::guard('web')->login($owner, false);
        request()->session()->regenerate();
        request()->session()->put(StandaloneAccess::SESSION_VERSION_KEY, $owner->auth_session_version);

        return 'pre-commit-session';
    });
    Route::middleware(['web', 'bfc.auth'])->get(
        '/_bfc-test/post-commit-session',
        static fn (): string => 'stale-session-authenticated',
    );
    $login = $this->get('/_bfc-test/pre-commit-session')->assertOk();
    $sessionCookie = collect($login->headers->getCookies())->sole(
        static fn (Cookie $cookie): bool => $cookie->getName() === config('session.cookie'),
    );
    $savedSession = (array) DB::table('sessions')->where('user_id', $owner->getKey())->sole();
    $service = app(ManagedTransitions::class);
    $transition = $service->prepare($owner, ManagedTransitionDirection::Exit);
    $transition = $service->fetchRoster($transition);
    $transition = $service->proposeDefault($transition);
    $fixture->transform = static function (string $leg, array $payload) use ($savedSession): array {
        if ($leg === 'T4') {
            DB::table('sessions')->insert($savedSession);
        }

        return $payload;
    };

    $completed = $service->complete($owner, $transition);

    expect($completed->status)->toBe(ManagedTransitionStatus::Acknowledged)
        ->and($owner->refresh()->auth_session_version)->toBe(2)
        ->and(DB::table('sessions')->where('id', $savedSession['id'])->exists())->toBeTrue();
    Auth::forgetGuards();
    $this->withUnencryptedCookie($sessionCookie->getName(), $sessionCookie->getValue())
        ->getJson('/_bfc-test/post-commit-session')
        ->assertUnauthorized()
        ->assertDontSee('stale-session-authenticated');
    $this->assertGuest();
});

it('rolls back every exit effect when the resulting Owner cannot authenticate or recover', function (): void {
    $roster = [[
        'scalpels_id' => 'owner-subject', 'membership_status' => 'active', 'role' => 'owner',
        'display_name' => 'Inaccessible Owner', 'contact_email' => 'unreachable-owner@example.test', 'contact_email_verified' => false,
    ]];
    [$owner] = p4dConfigure(ManagedTransitionDirection::Exit, $roster);
    $transition = p4dProposed($owner, ManagedTransitionDirection::Exit, [[
        'scalpels_id' => 'owner-subject', 'local_kind' => 'user', 'local_id' => (string) $owner->getKey(),
        'role' => 'owner', 'disposition' => 'link', 'final_email' => 'unreachable-owner@example.test',
    ]]);
    $transition = app(ManagedTransitions::class)->stage($transition);
    $before = p4dStateExceptAttempt();

    expect(fn () => app(ManagedTransitions::class)->commit($transition, $owner))
        ->toThrow(ManagedAuthRefused::class)
        ->and(p4dStateExceptAttempt())->toBe($before)
        ->and(InstallationAuthority::current()->mode)->toBe(AuthorityMode::Managed)
        ->and(InstallationAuthority::current()->generation)->toBe(7)
        ->and($transition->refresh()->status)->toBe(ManagedTransitionStatus::Staged)
        ->and($transition->local_commit_receipt)->toBeNull();
});

it('keeps real post-exit standalone edits byte-stable against each delayed response class', function (string $class): void {
    [$transition, $owner, $retained] = p4dCompletedExit();
    $retained->forceFill(['email' => 'edited-after-exit@example.test', 'role' => 'member'])->save();
    $edited = $retained->refresh()->getAttributes();
    $transitionBefore = $transition->refresh()->getAttributes();
    $before = p4dStateExceptAttempt();
    $oldConnection = new ManagedAuthConnection(
        'https://issuer.example.test',
        'transition-connection',
        'transition-organization',
        'transition-installation',
        7,
        'https://transition-authority.example.test',
        'transition-secret',
        null,
    );

    $operation = match ($class) {
        'login' => fn () => $this->get(route('bfc.managed.login', absolute: false))->assertNotFound(),
        'exchange' => fn () => app(ManagedMembershipResponses::class)->applyExchange(
            $oldConnection,
            new ManagedAuthExchange(
                (string) $owner->scalpels_id,
                'old-membership',
                'active',
                'active',
                'member',
                'Delayed Exchange',
                'old-exchange@example.test',
                true,
                99,
                999,
                new DateTimeImmutable('2026-09-12T00:00:00+00:00'),
            ),
        ),
        'confirmation' => fn () => app(ManagedMembershipResponses::class)->applyConfirmation(
            $oldConnection,
            $owner,
            new ManagedAuthConfirmation(
                (string) $owner->scalpels_id,
                'removed',
                'active',
                'member',
                99,
                999,
                new DateTimeImmutable('2026-09-12T00:00:00+00:00'),
            ),
        ),
        'roster' => fn () => app(ManagedTransitions::class)->fetchRoster(p4dStaleTransition($transition, ManagedTransitionStatus::Prepared)),
        'stage' => fn () => app(ManagedTransitions::class)->stage(p4dStaleTransition($transition, ManagedTransitionStatus::Proposed)),
        'ack' => fn () => app(ManagedTransitions::class)->acknowledge(p4dStaleTransition($transition, ManagedTransitionStatus::Committed)),
        default => throw new RuntimeException('Unknown delayed response class.'),
    };

    if ($class === 'login') {
        $operation();
    } else {
        expect($operation)->toThrow(ManagedAuthRefused::class);
    }

    expect($retained->refresh()->getAttributes())->toBe($edited)
        ->and(p4dStateExceptAttempt())->toBe($before)
        ->and(InstallationAuthority::current()->mode)->toBe(AuthorityMode::Standalone)
        ->and(InstallationAuthority::current()->generation)->toBe(8)
        ->and($transition->refresh()->getAttributes())->toBe($transitionBefore);
})->with(['login', 'exchange', 'confirmation', 'roster', 'stage', 'ack']);

it('rejects an in-flight transition response released only after exit and standalone edits complete', function (string $leg): void {
    $roster = [[
        'scalpels_id' => 'owner-subject', 'membership_status' => 'active', 'role' => 'owner',
        'display_name' => 'Delayed Owner', 'contact_email' => 'standalone-owner@example.test', 'contact_email_verified' => true,
    ]];
    [$owner, $fixture] = p4dConfigure(ManagedTransitionDirection::Exit, $roster);
    $retained = User::query()->create(['name' => 'Delayed Retained', 'email' => 'delayed+bfc@example.test']);
    $retained->forceFill(['role' => 'admin', 'status' => 'active', 'email_is_generated' => true])->save();
    $service = app(ManagedTransitions::class);
    $transition = $service->prepare($owner, ManagedTransitionDirection::Exit);
    if ($leg !== 'T2') {
        $transition = $service->fetchRoster($transition);
        $transition = $service->proposeDefault($transition);
    }
    if ($leg === 'T4') {
        $transition = $service->stage($transition);
        $transition = $service->commit($transition, $owner);
    }
    $expectedState = null;
    $expectedTransition = null;
    $edited = null;
    $fixture->transform = function (string $responseLeg, array $payload) use (
        $fixture,
        $leg,
        $service,
        $transition,
        $owner,
        $retained,
        &$expectedState,
        &$expectedTransition,
        &$edited,
    ): array {
        if ($responseLeg !== $leg) {
            return $payload;
        }

        $fixture->transform = null;
        if ($leg === 'T2') {
            $current = $service->fetchRoster($transition->refresh());
            $current = $service->proposeDefault($current);
            $service->complete($owner->refresh(), $current);
        } else {
            $current = $service->recover($transition->refresh());
            if ($leg === 'T3') {
                $service->complete($owner->refresh(), $current);
            }
        }
        $retained->refresh()->forceFill([
            'email' => 'edited-after-delayed-'.$leg.'@example.test',
            'role' => 'member',
        ])->save();
        $edited = $retained->refresh()->getAttributes();
        $expectedState = p4dStateExceptAttempt();
        $expectedTransition = $transition->refresh()->getAttributes();

        return $payload;
    };

    $operation = match ($leg) {
        'T2' => fn (): ManagedTransition => $service->fetchRoster($transition),
        'T3' => fn (): ManagedTransition => $service->stage($transition),
        'T4' => fn (): ManagedTransition => $service->acknowledge($transition),
    };

    expect($operation)->toThrow(ManagedAuthRefused::class)
        ->and($edited)->not->toBeNull()
        ->and($retained->refresh()->getAttributes())->toBe($edited)
        ->and(p4dStateExceptAttempt())->toBe($expectedState)
        ->and($transition->refresh()->getAttributes())->toBe($expectedTransition)
        ->and(InstallationAuthority::current()->mode)->toBe(AuthorityMode::Standalone)
        ->and(collect($fixture->calls)->where('leg', $leg))->not->toBeEmpty();
})->with(['T2', 'T3', 'T4']);

function p4dStaleTransition(ManagedTransition $current, ManagedTransitionStatus $status): ManagedTransition
{
    $stale = $current->replicate();
    $stale->setAttribute($stale->getKeyName(), $current->getKey());
    $stale->exists = true;
    $stale->forceFill(['status' => $status]);

    return $stale;
}

/** @return list<array<string, mixed>> */
function p4dStoredMapping(ManagedTransition $transition): array
{
    return DB::table('bfc_managed_transition_mappings')
        ->where('managed_transition_id', $transition->id)
        ->orderBy('ordinal')
        ->get(['scalpels_id', 'local_kind', 'local_id', 'role', 'disposition', 'final_email'])
        ->map(static fn (object $row): array => (array) $row)
        ->all();
}

function p4dOwnerRequest(User $owner): Request
{
    $request = Request::create('/bfc/managed-transition/abandon', 'POST');
    $session = app('session')->driver();
    $session->start();
    $session->put(StandaloneAccess::SESSION_VERSION_KEY, $owner->auth_session_version);
    $request->setLaravelSession($session);
    $request->setUserResolver(static fn (): User => $owner);

    return $request;
}

/** @return list<string> */
function p4dReadTables(callable $operation): array
{
    $queries = [];
    DB::listen(static function ($query) use (&$queries): void {
        $queries[] = $query->sql;
    });
    $operation();
    $tables = [];
    foreach ($queries as $sql) {
        $statement = preg_replace('/\A(?:\s+|--[^\r\n]*(?:\R|\z)|\/\*.*?\*\/)+/s', '', $sql);
        if (! is_string($statement)
            || preg_match('/\A(?:select|with)\b/i', $statement) !== 1) {
            continue;
        }
        preg_match_all('/\b[a-z_][a-z0-9_]*\s+as\s*\(/i', $statement, $cteMatches);
        $cteNames = array_map(
            static fn (string $match): string => strtolower((string) preg_replace('/\s+as\s*\(.*/i', '', $match)),
            $cteMatches[0],
        );
        preg_match_all('/\b(?:from|join)\s+(?:["`]?[a-z_][a-z0-9_]*["`]?\.)?["`]?([a-z_][a-z0-9_]*)/i', $statement, $matches);
        foreach ($matches[1] as $table) {
            if (! in_array(strtolower($table), $cteNames, true)) {
                $tables[] = strtolower($table);
            }
        }
    }
    $tables = array_values(array_unique($tables));
    sort($tables);

    return $tables;
}

/** @return list<string> */
function p4dAllowedReadTables(): array
{
    return [
        'bfc_authority',
        'bfc_managed_transition_mappings',
        'bfc_managed_transition_roster_cursors',
        'bfc_managed_transition_roster_members',
        'bfc_managed_transitions',
        'invitations',
        'offboarded_subjects',
        'pragma_table_xinfo',
        'sessions',
        'sqlite_master',
        'users',
    ];
}

it('rejoins by the preserved external identity key and never by a colliding email', function (): void {
    [, $owner, , , $fixture] = p4dCompletedExit();
    $ownerId = (string) $owner->getKey();
    $owner->forceFill(['email' => 'locally-edited-owner@example.test'])->save();
    $collision = User::query()->create(['name' => 'Collision Holder', 'email' => 'new-subject-contact@example.test']);
    $collision->forceFill(['role' => 'member', 'status' => 'active'])->save();
    $fixture->generation = 8;
    $fixture->rosterPages = ['NULL' => [
        [
            'scalpels_id' => 'owner-subject', 'membership_status' => 'active', 'role' => 'owner',
            'display_name' => 'Rejoining Owner', 'contact_email' => 'new-authority-owner@example.test', 'contact_email_verified' => true,
        ],
        [
            'scalpels_id' => 'new-subject', 'membership_status' => 'active', 'role' => 'member',
            'display_name' => 'New Subject', 'contact_email' => 'new-subject-contact@example.test', 'contact_email_verified' => true,
        ],
    ]];
    $service = app(ManagedTransitions::class);
    $transition = $service->prepare($owner->refresh(), ManagedTransitionDirection::Adopt);
    $transition = $service->fetchRoster($transition);
    $excludedUsers = User::query()->whereKeyNot($ownerId)->get()->map(static fn (User $user): array => [
        'scalpels_id' => null, 'local_kind' => 'user', 'local_id' => (string) $user->getKey(),
        'role' => null, 'disposition' => 'exclude', 'final_email' => null,
    ])->all();
    $excludedInvitations = Invitation::query()->pending()->get()->map(static fn (Invitation $invitation): array => [
        'scalpels_id' => null, 'local_kind' => 'invitation', 'local_id' => (string) $invitation->getKey(),
        'role' => null, 'disposition' => 'exclude', 'final_email' => null,
    ])->all();
    $transition = $service->propose($transition, [
        [
            'scalpels_id' => 'owner-subject', 'local_kind' => 'user', 'local_id' => $ownerId,
            'role' => 'owner', 'disposition' => 'link', 'final_email' => 'locally-edited-owner@example.test',
        ],
        [
            'scalpels_id' => 'new-subject', 'local_kind' => null, 'local_id' => null,
            'role' => null, 'disposition' => 'defer_to_managed_jit', 'final_email' => null,
        ],
        ...$excludedUsers,
        ...$excludedInvitations,
    ]);
    $ownerMapping = DB::table('bfc_managed_transition_mappings')
        ->where('managed_transition_id', $transition->id)
        ->where('scalpels_id', 'owner-subject')
        ->first();
    $newMapping = DB::table('bfc_managed_transition_mappings')
        ->where('managed_transition_id', $transition->id)
        ->where('scalpels_id', 'new-subject')
        ->first();

    expect($ownerMapping)->not->toBeNull()
        ->and($ownerMapping->local_id)->toBe($ownerId)
        ->and($ownerMapping->final_email)->toBe('locally-edited-owner@example.test')
        ->and($newMapping)->not->toBeNull()
        ->and($newMapping->disposition)->toBe('defer_to_managed_jit')
        ->and($newMapping->local_id)->toBeNull();

    $service->complete($owner->refresh(), $transition);

    expect((string) User::query()->where('scalpels_id', 'owner-subject')->sole()->getKey())->toBe($ownerId)
        ->and(User::query()->whereKey($collision->getKey())->sole()->scalpels_id)->toBeNull()
        ->and(User::query()->where('scalpels_id', 'new-subject')->exists())->toBeFalse();
});

it('retains authority and retry records through removed entitlement state and long interrupted phases', function (
    ManagedTransitionDirection $direction,
    string $phase,
): void {
    $contactEmail = $direction === ManagedTransitionDirection::Exit
        ? 'standalone-owner@example.test'
        : 'p4d-owner@example.test';
    $roster = [[
        'scalpels_id' => 'owner-subject', 'membership_status' => 'active', 'role' => 'owner',
        'display_name' => 'Durable Owner', 'contact_email' => $contactEmail, 'contact_email_verified' => true,
    ]];
    [$owner, $fixture] = p4dConfigure($direction, $roster);
    $service = app(ManagedTransitions::class);
    if ($phase === 'preparing') {
        $fixture->crashAfterExecution = 'T1';
        expect(fn () => $service->prepare($owner, $direction))->toThrow(ManagedAuthRefused::class);
        $transition = ManagedTransition::query()->sole();
    } else {
        $transition = $service->prepare($owner, $direction);
    }
    if (! in_array($phase, ['preparing', 'prepared'], true)) {
        $transition = $service->fetchRoster($transition);
    }
    if (in_array($phase, ['proposed', 'staging', 'staged'], true)) {
        $transition = $service->proposeDefault($transition);
    }
    if ($phase === 'staging') {
        $fixture->crashBeforeExecution = 'T3';
        expect(fn () => $service->stage($transition))->toThrow(ManagedAuthRefused::class);
        $transition = $transition->refresh();
    } elseif ($phase === 'staged') {
        $transition = $service->stage($transition);
    }
    DB::table('integration_entitlements')->insert([
        'id' => (string) Str::uuid(),
        'integration_namespace' => 'billing-control',
        'external_subject' => 'transition-installation',
        'entitlement_version' => 3,
        'created_at' => now(),
        'updated_at' => now(),
    ]);
    DB::table('integration_events')->insert([
        'id' => (string) Str::uuid(),
        'integration_namespace' => 'billing-control',
        'event_id' => 'cancelled-'.$phase,
        'external_subject' => 'transition-installation',
        'event_kind' => 'subscription.cancelled',
        'entitlement_version' => 4,
        'applied' => true,
        'created_at' => now(),
        'updated_at' => now(),
    ]);
    DB::table('integration_events')->delete();
    DB::table('integration_entitlements')->delete();
    $originalTransitionId = (string) $transition->getKey();
    $originalTransitionCreatedAt = $transition->getRawOriginal('created_at');
    $requestId = $transition->transition_request_id;
    $authorityBefore = (array) DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->sole();
    $connectionFields = [
        'key', 'issuer', 'connection_id', 'organization_id', 'installation_id', 'authority_base_url', 'created_at',
    ];
    $connectionBefore = array_intersect_key($authorityBefore, array_flip($connectionFields));
    $transitionConnectionFields = [
        'issuer', 'connection_id', 'organization_id', 'installation_id', 'authority_base_url',
        'authority_ca_bundle', 'client_credential_reference',
    ];
    $transitionConnectionBefore = array_intersect_key($transition->getAttributes(), array_flip($transitionConnectionFields));
    $this->travel(10)->years();

    $callsBeforeRecovery = count($fixture->calls);
    $recovered = null;
    $recoveryReadTables = p4dReadTables(function () use ($service, $transition, &$recovered): void {
        $recovered = $service->recover($transition->refresh());
    });
    $recoveryCalls = array_column(array_slice($fixture->calls, $callsBeforeRecovery), 'leg');
    $expectedRecoveryCalls = match ($phase) {
        'preparing' => ['T6', 'T1'],
        'staging' => ['T5', 'T3'],
        default => ['T5'],
    };
    expect($recovered)->toBeInstanceOf(ManagedTransition::class)
        ->and($recoveryCalls)->toBe($expectedRecoveryCalls)
        ->and($recoveryReadTables)->not->toBe([])
        ->and(array_values(array_diff($recoveryReadTables, p4dAllowedReadTables())))->toBe([]);
    expect((array) DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->sole())
        ->toBe($authorityBefore)
        ->and((string) $recovered->getKey())->toBe($originalTransitionId);
    if ($recovered->status === ManagedTransitionStatus::Prepared) {
        $recovered = $service->fetchRoster($recovered);
    }
    if ($recovered->status === ManagedTransitionStatus::Rostered) {
        $recovered = $service->proposeDefault($recovered);
    }
    $completed = $service->complete($owner->refresh(), $recovered);
    $authorityAfter = (array) DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->sole();

    expect($completed->status)->toBe(ManagedTransitionStatus::Acknowledged)
        ->and((string) $completed->getKey())->toBe($originalTransitionId)
        ->and($completed->getRawOriginal('created_at'))->toBe($originalTransitionCreatedAt)
        ->and($completed->transition_request_id)->toBe($requestId)
        ->and(array_intersect_key($authorityAfter, array_flip($connectionFields)))->toBe($connectionBefore)
        ->and(array_intersect_key($completed->getAttributes(), array_flip($transitionConnectionFields)))->toBe($transitionConnectionBefore)
        ->and(ManagedTransition::query()->whereKey($originalTransitionId)->count())->toBe(1);
})->with([
    'adopt preparing' => [ManagedTransitionDirection::Adopt, 'preparing'],
    'adopt prepared' => [ManagedTransitionDirection::Adopt, 'prepared'],
    'adopt rostered' => [ManagedTransitionDirection::Adopt, 'rostered'],
    'adopt proposed' => [ManagedTransitionDirection::Adopt, 'proposed'],
    'adopt staging' => [ManagedTransitionDirection::Adopt, 'staging'],
    'adopt staged' => [ManagedTransitionDirection::Adopt, 'staged'],
    'exit preparing' => [ManagedTransitionDirection::Exit, 'preparing'],
    'exit prepared' => [ManagedTransitionDirection::Exit, 'prepared'],
    'exit rostered' => [ManagedTransitionDirection::Exit, 'rostered'],
    'exit proposed' => [ManagedTransitionDirection::Exit, 'proposed'],
    'exit staging' => [ManagedTransitionDirection::Exit, 'staging'],
    'exit staged' => [ManagedTransitionDirection::Exit, 'staged'],
]);

it('enumerates T6 recovery outcomes under the frozen read inventory', function (string $outcome): void {
    $roster = [[
        'scalpels_id' => 'owner-subject', 'membership_status' => 'active', 'role' => 'owner',
        'display_name' => 'T6 Owner', 'contact_email' => 't6-owner@example.test', 'contact_email_verified' => true,
    ]];
    [$owner, $fixture] = p4dConfigure(ManagedTransitionDirection::Adopt, $roster);
    $fixture->crashBeforeExecution = $outcome === 'not_found' ? 'T1' : null;
    $fixture->crashAfterExecution = $outcome === 'not_found' ? null : 'T1';
    expect(fn () => app(ManagedTransitions::class)->prepare($owner, ManagedTransitionDirection::Adopt))
        ->toThrow(ManagedAuthRefused::class);
    $transition = ManagedTransition::query()->sole();
    $fixture->transform = static function (string $leg, array $payload) use ($outcome): array {
        if ($leg === 'T6' && $outcome !== 'not_found') {
            $payload['status'] = $outcome;
        }

        return $payload;
    };
    $recovered = null;
    $refused = false;
    $callsBeforeRecovery = count($fixture->calls);
    $readTables = p4dReadTables(function () use ($transition, &$recovered, &$refused): void {
        try {
            $recovered = app(ManagedTransitions::class)->recover($transition);
        } catch (ManagedAuthRefused) {
            $refused = true;
        }
    });

    expect(array_column(array_slice($fixture->calls, $callsBeforeRecovery), 'leg'))->toBe(['T6'])
        ->and($readTables)->not->toBe([])
        ->and(array_values(array_diff($readTables, p4dAllowedReadTables())))->toBe([]);
    if ($outcome === 'unknown') {
        expect($refused)->toBeTrue()
            ->and($recovered)->toBeNull()
            ->and($transition->refresh()->status)->toBe(ManagedTransitionStatus::Preparing);
    } else {
        expect($refused)->toBeFalse()
            ->and($recovered)->toBeInstanceOf(ManagedTransition::class)
            ->and($recovered->status)->toBe(ManagedTransitionStatus::Abandoned);
    }
})->with(['not_found', 'abandoned', 'unknown']);

it('enumerates post-commit and terminal recovery outcomes under the frozen read inventory', function (
    ManagedTransitionDirection $direction,
    string $case,
): void {
    $roster = [[
        'scalpels_id' => 'owner-subject', 'membership_status' => 'active', 'role' => 'owner',
        'display_name' => 'Recovery Owner', 'contact_email' => 'recovery-owner@example.test', 'contact_email_verified' => true,
    ]];
    [$owner, $fixture] = p4dConfigure($direction, $roster);
    $service = app(ManagedTransitions::class);
    $transition = $service->prepare($owner, $direction);
    if (in_array($case, ['prepared abandoned', 'prepared unknown', 'abandoned'], true)) {
        if ($case === 'abandoned') {
            $transition = $service->abandon(p4dOwnerRequest($owner), $transition);
        }
    } else {
        $transition = $service->fetchRoster($transition);
        $transition = $direction === ManagedTransitionDirection::Adopt
            ? $service->propose($transition, [[
                'scalpels_id' => 'owner-subject',
                'local_kind' => 'user',
                'local_id' => (string) $owner->getKey(),
                'role' => 'owner',
                'disposition' => 'link',
                'final_email' => 'recovery-owner@example.test',
            ]])
            : $service->proposeDefault($transition);
        $transition = $service->stage($transition);
        $transition = $service->commit($transition, $owner);
        if ($case === 'acknowledging staged') {
            $fixture->crashBeforeExecution = 'T4';
            expect(fn () => $service->acknowledge($transition))->toThrow(ManagedAuthRefused::class);
            $transition = $transition->refresh();
        } elseif ($case === 'acknowledging acknowledged') {
            $fixture->crashAfterExecution = 'T4';
            expect(fn () => $service->acknowledge($transition))->toThrow(ManagedAuthRefused::class);
            $transition = $transition->refresh();
        } elseif ($case === 'acknowledged') {
            $transition = $service->acknowledge($transition);
        }
    }
    if (str_starts_with($case, 'prepared ')) {
        $authorityStatus = substr($case, strlen('prepared '));
        $fixture->transform = static function (string $leg, array $payload) use ($authorityStatus): array {
            if ($leg === 'T5') {
                $payload['status'] = $authorityStatus;
            }

            return $payload;
        };
    }
    $callsBeforeRecovery = count($fixture->calls);
    $recovered = null;
    $refused = false;
    $readTables = p4dReadTables(function () use ($service, $transition, &$recovered, &$refused): void {
        try {
            $recovered = $service->recover($transition);
        } catch (ManagedAuthRefused) {
            $refused = true;
        }
    });
    $recoveryCalls = array_column(array_slice($fixture->calls, $callsBeforeRecovery), 'leg');
    $expectedCalls = match ($case) {
        'committed', 'acknowledging staged' => ['T5', 'T4'],
        'acknowledging acknowledged', 'prepared abandoned', 'prepared unknown' => ['T5'],
        'acknowledged', 'abandoned' => [],
    };

    expect($recoveryCalls)->toBe($expectedCalls)
        ->and($readTables)->not->toBe([])
        ->and(array_values(array_diff($readTables, p4dAllowedReadTables())))->toBe([]);
    if ($case === 'prepared unknown') {
        expect($refused)->toBeTrue()
            ->and($transition->refresh()->status)->toBe(ManagedTransitionStatus::Prepared);
    } else {
        $expectedStatus = $case === 'abandoned' || $case === 'prepared abandoned'
            ? ManagedTransitionStatus::Abandoned
            : ManagedTransitionStatus::Acknowledged;
        expect($refused)->toBeFalse()
            ->and($recovered)->toBeInstanceOf(ManagedTransition::class)
            ->and($recovered->status)->toBe($expectedStatus);
    }
})->with([
    'adopt committed' => [ManagedTransitionDirection::Adopt, 'committed'],
    'exit committed' => [ManagedTransitionDirection::Exit, 'committed'],
    'adopt acknowledging staged' => [ManagedTransitionDirection::Adopt, 'acknowledging staged'],
    'exit acknowledging staged' => [ManagedTransitionDirection::Exit, 'acknowledging staged'],
    'adopt acknowledging acknowledged' => [ManagedTransitionDirection::Adopt, 'acknowledging acknowledged'],
    'exit acknowledging acknowledged' => [ManagedTransitionDirection::Exit, 'acknowledging acknowledged'],
    'prepared abandoned' => [ManagedTransitionDirection::Adopt, 'prepared abandoned'],
    'prepared unknown' => [ManagedTransitionDirection::Adopt, 'prepared unknown'],
    'acknowledged' => [ManagedTransitionDirection::Adopt, 'acknowledged'],
    'abandoned' => [ManagedTransitionDirection::Adopt, 'abandoned'],
]);

it('enumerates every transition operation in both directions and permits only frozen transition-store reads', function (
    string $operation,
    ManagedTransitionDirection $direction,
): void {
    $expectedOperations = [
        'abandon', 'acknowledge', 'commit', 'complete', 'fetchRoster', 'prepare', 'propose',
        'proposeDefault', 'proposeForOwner', 'recover', 'stage',
    ];
    $actualOperations = collect((new ReflectionClass(ManagedTransitions::class))->getMethods(ReflectionMethod::IS_PUBLIC))
        ->reject(static fn (ReflectionMethod $method): bool => $method->isConstructor())
        ->map(static fn (ReflectionMethod $method): string => $method->getName())
        ->sort()
        ->values()
        ->all();
    $roster = [[
        'scalpels_id' => 'owner-subject', 'membership_status' => 'active', 'role' => 'owner',
        'display_name' => 'Independent Owner', 'contact_email' => 'independent-owner@example.test', 'contact_email_verified' => true,
    ]];
    [$owner, $fixture] = p4dConfigure($direction, $roster);
    $service = app(ManagedTransitions::class);
    $link = [[
        'scalpels_id' => 'owner-subject', 'local_kind' => 'user', 'local_id' => (string) $owner->getKey(),
        'role' => 'owner', 'disposition' => 'link', 'final_email' => 'independent-owner@example.test',
    ]];

    if ($operation === 'prepare') {
        $invoke = fn (): ManagedTransition => $service->prepare($owner, $direction);
    } else {
        $transition = $service->prepare($owner, $direction);
        if ($operation === 'fetchRoster') {
            $invoke = fn (): ManagedTransition => $service->fetchRoster($transition);
        } elseif ($operation === 'abandon') {
            $invoke = fn (): ManagedTransition => $service->abandon(p4dOwnerRequest($owner), $transition);
        } else {
            $transition = $service->fetchRoster($transition);
            if ($operation === 'propose') {
                $invoke = fn (): ManagedTransition => $service->propose($transition, $link);
            } elseif ($operation === 'proposeDefault') {
                $invoke = fn (): ManagedTransition => $service->proposeDefault($transition);
            } else {
                $transition = $service->propose($transition, $link);
                if ($operation === 'proposeForOwner') {
                    $mapping = p4dStoredMapping($transition);
                    $invoke = fn (): ManagedTransition => $service->proposeForOwner($owner, $transition, $mapping);
                } elseif ($operation === 'stage') {
                    $invoke = fn (): ManagedTransition => $service->stage($transition);
                } elseif ($operation === 'complete') {
                    $invoke = fn (): ManagedTransition => $service->complete($owner, $transition);
                } elseif ($operation === 'recover') {
                    $fixture->crashAfterExecution = 'T3';
                    expect(fn () => $service->stage($transition))->toThrow(ManagedAuthRefused::class);
                    $transition = $transition->refresh();
                    $invoke = fn (): ManagedTransition => $service->recover($transition);
                } else {
                    $transition = $service->stage($transition);
                    if ($operation === 'commit') {
                        $invoke = fn (): ManagedTransition => $service->commit($transition, $owner);
                    } else {
                        $transition = $service->commit($transition, $owner);
                        $invoke = fn (): ManagedTransition => $service->acknowledge($transition);
                    }
                }
            }
        }
    }

    $result = null;
    $readTables = p4dReadTables(function () use ($invoke, &$result): void {
        $result = $invoke();
    });
    $unexpected = array_values(array_diff($readTables, p4dAllowedReadTables()));
    $expectedStatus = match ($operation) {
        'prepare' => ManagedTransitionStatus::Prepared,
        'fetchRoster' => ManagedTransitionStatus::Rostered,
        'abandon' => ManagedTransitionStatus::Abandoned,
        'propose', 'proposeDefault', 'proposeForOwner' => ManagedTransitionStatus::Proposed,
        'stage', 'recover' => ManagedTransitionStatus::Staged,
        'commit' => ManagedTransitionStatus::Committed,
        'complete', 'acknowledge' => ManagedTransitionStatus::Acknowledged,
    };

    expect($actualOperations)->toBe($expectedOperations)
        ->and($result)->toBeInstanceOf(ManagedTransition::class)
        ->and($result->status)->toBe($expectedStatus)
        ->and($readTables)->not->toBe([])
        ->and($unexpected)->toBe([]);
})->with([
    'adopt abandon' => ['abandon', ManagedTransitionDirection::Adopt],
    'exit abandon' => ['abandon', ManagedTransitionDirection::Exit],
    'adopt acknowledge' => ['acknowledge', ManagedTransitionDirection::Adopt],
    'exit acknowledge' => ['acknowledge', ManagedTransitionDirection::Exit],
    'adopt commit' => ['commit', ManagedTransitionDirection::Adopt],
    'exit commit' => ['commit', ManagedTransitionDirection::Exit],
    'adopt complete' => ['complete', ManagedTransitionDirection::Adopt],
    'exit complete' => ['complete', ManagedTransitionDirection::Exit],
    'adopt fetchRoster' => ['fetchRoster', ManagedTransitionDirection::Adopt],
    'exit fetchRoster' => ['fetchRoster', ManagedTransitionDirection::Exit],
    'adopt prepare' => ['prepare', ManagedTransitionDirection::Adopt],
    'exit prepare' => ['prepare', ManagedTransitionDirection::Exit],
    'adopt propose' => ['propose', ManagedTransitionDirection::Adopt],
    'exit propose' => ['propose', ManagedTransitionDirection::Exit],
    'adopt proposeDefault' => ['proposeDefault', ManagedTransitionDirection::Adopt],
    'exit proposeDefault' => ['proposeDefault', ManagedTransitionDirection::Exit],
    'adopt proposeForOwner' => ['proposeForOwner', ManagedTransitionDirection::Adopt],
    'exit proposeForOwner' => ['proposeForOwner', ManagedTransitionDirection::Exit],
    'adopt recover' => ['recover', ManagedTransitionDirection::Adopt],
    'exit recover' => ['recover', ManagedTransitionDirection::Exit],
    'adopt stage' => ['stage', ManagedTransitionDirection::Adopt],
    'exit stage' => ['stage', ManagedTransitionDirection::Exit],
]);

it('proves the transition read inventory rejects ordinary and CTE commercial-store reads', function (callable $read): void {
    $readTables = p4dReadTables($read);

    expect(array_values(array_diff($readTables, p4dAllowedReadTables())))
        ->toBe(['integration_entitlements']);
})->with([
    'ordinary select' => static fn (): bool => DB::table('integration_entitlements')->exists(),
    'commented CTE select' => static fn (): array => DB::select(<<<'SQL'
        /* inventory control */
        WITH entitlement_probe AS (SELECT id FROM integration_entitlements)
        SELECT id FROM entitlement_probe
        SQL),
]);

it('enumerates every transition HTTP surface in both directions under the frozen read inventory', function (
    string $surface,
    ManagedTransitionDirection $direction,
): void {
    $expectedMethods = ['complete', 'edit', 'index', 'store', 'update'];
    $actualMethods = collect((new ReflectionClass(ManageTransitions::class))->getMethods(ReflectionMethod::IS_PUBLIC))
        ->reject(static fn (ReflectionMethod $method): bool => $method->isConstructor())
        ->map(static fn (ReflectionMethod $method): string => $method->getName())
        ->sort()
        ->values()
        ->all();
    $expectedRoutes = [
        'bfc.transitions.complete',
        'bfc.transitions.edit',
        'bfc.transitions.index',
        'bfc.transitions.store',
        'bfc.transitions.update',
    ];
    $actualRoutes = collect(Route::getRoutes()->getRoutes())
        ->filter(static fn ($route): bool => str_starts_with($route->getActionName(), ManageTransitions::class.'@'))
        ->pluck('action.as')
        ->sort()
        ->values()
        ->all();
    $roster = [[
        'scalpels_id' => 'owner-subject', 'membership_status' => 'active', 'role' => 'owner',
        'display_name' => 'Surface Owner', 'contact_email' => 'surface-inventory@example.test', 'contact_email_verified' => true,
    ]];
    [$owner] = p4dConfigure($direction, $roster);
    $this->actingAsVersioned($owner);

    if ($surface === 'index') {
        $invoke = fn () => $this->get(route('bfc.transitions.index', $direction->value, false));
    } elseif ($surface === 'store') {
        $invoke = fn () => $this->post(route('bfc.transitions.store', $direction->value, false));
    } else {
        $transition = p4dProposed($owner, $direction, [[
            'scalpels_id' => 'owner-subject', 'local_kind' => 'user', 'local_id' => (string) $owner->getKey(),
            'role' => 'owner', 'disposition' => 'link', 'final_email' => 'surface-inventory@example.test',
        ]]);
        $updatePayload = $direction === ManagedTransitionDirection::Adopt
            ? [
                'roster' => [[
                    'scalpels_id' => 'owner-subject',
                    'choice' => 'link:user:'.$owner->getKey(),
                    'final_email' => 'surface-inventory@example.test',
                ]],
                'locals' => [[
                    'local_kind' => 'user',
                    'local_id' => (string) $owner->getKey(),
                ]],
            ]
            : [
                'locals' => [[
                    'local_kind' => 'user',
                    'local_id' => (string) $owner->getKey(),
                    'choice' => 'link:owner-subject',
                    'role' => 'owner',
                    'final_email' => 'surface-inventory@example.test',
                ]],
            ];
        $invoke = match ($surface) {
            'edit' => fn () => $this->get(route('bfc.transitions.edit', $transition, false)),
            'update' => fn () => $this->put(route('bfc.transitions.update', $transition, false), $updatePayload),
            'complete' => fn () => $this->post(route('bfc.transitions.complete', $transition, false)),
        };
    }

    $response = null;
    $readTables = p4dReadTables(function () use ($invoke, &$response): void {
        $response = $invoke();
    });

    expect($actualMethods)->toBe($expectedMethods)
        ->and($actualRoutes)->toBe($expectedRoutes)
        ->and($response)->not->toBeNull()
        ->and($readTables)->not->toBe([])
        ->and(array_values(array_diff($readTables, p4dAllowedReadTables())))->toBe([]);
    if (in_array($surface, ['edit', 'index'], true)) {
        $response->assertOk();
    } else {
        $response->assertRedirect();
    }
    if ($surface === 'store') {
        expect(ManagedTransition::query()->sole()->status)->toBe(ManagedTransitionStatus::Proposed);
    } elseif ($surface === 'update') {
        expect($transition->refresh()->status)->toBe(ManagedTransitionStatus::Proposed)
            ->and(DB::table('bfc_managed_transition_mappings')
                ->where('managed_transition_id', $transition->id)
                ->where('scalpels_id', 'owner-subject')
                ->value('final_email'))->toBe('surface-inventory@example.test');
    } elseif ($surface === 'complete') {
        expect($transition->refresh()->status)->toBe(ManagedTransitionStatus::Acknowledged);
    }
})->with([
    'adopt complete' => ['complete', ManagedTransitionDirection::Adopt],
    'exit complete' => ['complete', ManagedTransitionDirection::Exit],
    'adopt edit' => ['edit', ManagedTransitionDirection::Adopt],
    'exit edit' => ['edit', ManagedTransitionDirection::Exit],
    'adopt index' => ['index', ManagedTransitionDirection::Adopt],
    'exit index' => ['index', ManagedTransitionDirection::Exit],
    'adopt store' => ['store', ManagedTransitionDirection::Adopt],
    'exit store' => ['store', ManagedTransitionDirection::Exit],
    'adopt update' => ['update', ManagedTransitionDirection::Adopt],
    'exit update' => ['update', ManagedTransitionDirection::Exit],
]);
