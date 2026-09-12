<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Auth\CredentialResolver;
use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\Exceptions\ManagedAuthRefused;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageTransitions;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureStandaloneAuthority;
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
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
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
        'managed_membership_status' => 'active',
        'managed_membership_role' => 'admin',
        'managed_membership_generation' => 7,
        'managed_membership_roster_version' => 40,
        'managed_membership_response_sequence' => 70,
    ])->save();
    $excluded = User::query()->create(['name' => 'Excluded Exit', 'email' => 'excluded-exit@example.test']);
    $excluded->forceFill(['role' => 'member', 'status' => 'active'])->save();
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
    $excluded->forceFill(['role' => 'member', 'status' => 'active', 'original_contact_email' => 'historical@example.test'])->save();
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
        ->and($excluded->status)->toBe('inactive')
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

it('rolls back every protected store when exact generation postcondition fails after local effects', function (): void {
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

it('holds the standalone authority read lock across every mutating surface handler', function (): void {
    Route::middleware(EnsureStandaloneAuthority::class)->post(
        '/_bfc-test/standalone-lock-window',
        static fn (): array => ['transaction_level' => DB::transactionLevel()],
    );

    $this->post('/_bfc-test/standalone-lock-window')
        ->assertOk()
        ->assertJsonPath('transaction_level', 2);
});

it('establishes an accessible standalone Owner and applies every exit disposition and invalidation', function (): void {
    [$transition, $owner, $retained, $kept] = p4dCompletedExit();
    $created = User::query()->where('scalpels_id', 'invited-subject')->sole();

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
        ->and(User::query()->where('email', 'excluded-exit@example.test')->sole()->status)->toBe('inactive')
        ->and(Invitation::query()->where('email', 'cancelled-invitation@example.test')->sole()->cancelled_at)->not->toBeNull()
        ->and(DB::table('sessions')->count())->toBe(0)
        ->and(DB::table('password_reset_tokens')->count())->toBe(0)
        ->and(Credential::query()->whereNotNull('user_id')->whereNull('revoked_at')->count())->toBe(0)
        ->and(Credential::query()->where('name', 'exit-deployment-survives')->value('revoked_at'))->toBeNull()
        ->and(DB::table('bfc_authority')->value('managed_connection_status'))->toBeNull()
        ->and(DB::table('bfc_managed_handoffs')->whereNull('consumed_at')->count())->toBe(0);

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
        if (! str_starts_with(strtolower(ltrim($sql)), 'select')) {
            continue;
        }
        preg_match_all('/\b(?:from|join)\s+(?:["`]?[a-z_][a-z0-9_]*["`]?\.)?["`]?([a-z_][a-z0-9_]*)/i', $sql, $matches);
        foreach ($matches[1] as $table) {
            $tables[] = strtolower($table);
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
    $requestId = $transition->transition_request_id;
    $authorityKey = DB::table('bfc_authority')->value('key');
    $this->travel(10)->years();

    $recovered = $service->recover($transition->refresh());
    if ($recovered->status === ManagedTransitionStatus::Prepared) {
        $recovered = $service->fetchRoster($recovered);
    }
    if ($recovered->status === ManagedTransitionStatus::Rostered) {
        $recovered = $service->proposeDefault($recovered);
    }
    $completed = $service->complete($owner->refresh(), $recovered);

    expect($completed->status)->toBe(ManagedTransitionStatus::Acknowledged)
        ->and($completed->transition_request_id)->toBe($requestId)
        ->and(DB::table('bfc_authority')->value('key'))->toBe($authorityKey)
        ->and(DB::table('bfc_authority')->value('connection_id'))->toBe('transition-connection')
        ->and(ManagedTransition::query()->whereKey($completed->id)->exists())->toBeTrue();
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

it('enumerates every transition operation and permits reads only from the frozen transition stores', function (string $operation): void {
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
    [$owner, $fixture] = p4dConfigure(ManagedTransitionDirection::Adopt, $roster);
    $service = app(ManagedTransitions::class);
    $link = [[
        'scalpels_id' => 'owner-subject', 'local_kind' => 'user', 'local_id' => (string) $owner->getKey(),
        'role' => 'owner', 'disposition' => 'link', 'final_email' => 'independent-owner@example.test',
    ]];

    if ($operation === 'prepare') {
        $invoke = fn (): ManagedTransition => $service->prepare($owner, ManagedTransitionDirection::Adopt);
    } else {
        $transition = $service->prepare($owner, ManagedTransitionDirection::Adopt);
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

    $readTables = p4dReadTables($invoke);
    $unexpected = array_values(array_diff($readTables, p4dAllowedReadTables()));

    expect($actualOperations)->toBe($expectedOperations)
        ->and($readTables)->not->toBe([])
        ->and($unexpected)->toBe([]);
})->with([
    'abandon', 'acknowledge', 'commit', 'complete', 'fetchRoster', 'prepare', 'propose',
    'proposeDefault', 'proposeForOwner', 'recover', 'stage',
]);

it('proves the transition read inventory rejects a newly introduced commercial store', function (): void {
    $readTables = p4dReadTables(static fn (): bool => DB::table('integration_entitlements')->exists());

    expect(array_values(array_diff($readTables, p4dAllowedReadTables())))
        ->toBe(['integration_entitlements']);
});

it('enumerates every transition HTTP surface under the same frozen read inventory', function (string $surface): void {
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
    [$owner] = p4dConfigure(ManagedTransitionDirection::Adopt, $roster);
    $this->actingAsVersioned($owner);

    if ($surface === 'index') {
        $invoke = fn () => $this->get(route('bfc.transitions.index', ManagedTransitionDirection::Adopt->value, false));
    } elseif ($surface === 'store') {
        $invoke = fn () => $this->post(route('bfc.transitions.store', ManagedTransitionDirection::Adopt->value, false));
    } else {
        $transition = p4dProposed($owner, ManagedTransitionDirection::Adopt, [[
            'scalpels_id' => 'owner-subject', 'local_kind' => 'user', 'local_id' => (string) $owner->getKey(),
            'role' => 'owner', 'disposition' => 'link', 'final_email' => 'surface-inventory@example.test',
        ]]);
        $invoke = match ($surface) {
            'edit' => fn () => $this->get(route('bfc.transitions.edit', $transition, false)),
            'update' => fn () => $this->put(route('bfc.transitions.update', $transition, false), [
                'roster' => [[
                    'scalpels_id' => 'owner-subject',
                    'choice' => 'link:user:'.$owner->getKey(),
                    'final_email' => 'surface-inventory@example.test',
                ]],
                'locals' => [[
                    'local_kind' => 'user',
                    'local_id' => (string) $owner->getKey(),
                ]],
            ]),
            'complete' => fn () => $this->post(route('bfc.transitions.complete', $transition, false)),
        };
    }

    $readTables = p4dReadTables($invoke);

    expect($actualMethods)->toBe($expectedMethods)
        ->and($actualRoutes)->toBe($expectedRoutes)
        ->and($readTables)->not->toBe([])
        ->and(array_values(array_diff($readTables, p4dAllowedReadTables())))->toBe([]);
})->with(['complete', 'edit', 'index', 'store', 'update']);
