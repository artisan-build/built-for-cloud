<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\Exceptions\ManagedAuthRefused;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\ManagedAuthClient;
use ArtisanBuild\BuiltForCloud\ManagedAuthConfirmation;
use ArtisanBuild\BuiltForCloud\ManagedAuthConnection;
use ArtisanBuild\BuiltForCloud\ManagedAuthExchange;
use ArtisanBuild\BuiltForCloud\ManagedHandoff;
use ArtisanBuild\BuiltForCloud\ManagedMembershipResponses;
use ArtisanBuild\BuiltForCloud\ManagedOwnershipStatement;
use ArtisanBuild\BuiltForCloud\ManagedOwnershipSubject;
use ArtisanBuild\BuiltForCloud\StandaloneAccess;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\ManagedAuthorityFixture;
use ArtisanBuild\BuiltForCloud\User;
use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;

uses(RefreshDatabase::class);

function p4aConnection(): ManagedAuthConnection
{
    return new ManagedAuthConnection(
        'https://issuer.example.test',
        'connection-fixture',
        'organization-fixture',
        'installation-fixture',
        7,
        'https://authority.example.test',
        'fixture-client-secret',
        null,
    );
}

function p4aConfigureAuthority(): ManagedAuthorityFixture
{
    DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
        'mode' => AuthorityMode::Managed->value,
        'generation' => 7,
        'issuer' => 'https://issuer.example.test',
        'connection_id' => 'connection-fixture',
        'organization_id' => 'organization-fixture',
        'installation_id' => 'installation-fixture',
        'authority_base_url' => 'https://authority.example.test',
    ]);
    config([
        'built-for-cloud.managed.client_secret' => 'fixture-client-secret',
        'built-for-cloud.managed.ca_bundle' => null,
    ]);
    $fixture = new ManagedAuthorityFixture(
        'https://authority.example.test',
        'fixture-client-secret',
        'https://issuer.example.test',
        'connection-fixture',
        'organization-fixture',
        'installation-fixture',
        7,
    );
    Http::fake(fn (ClientRequest $request) => $fixture->respond($request));

    return $fixture;
}

function p4aUser(
    string $subject,
    string $role = 'member',
    string $status = 'active',
    int $sequence = 10,
): User {
    $user = User::query()->create([
        'name' => 'Local '.$subject,
        'email' => $subject.'@example.test',
    ]);
    $user->forceFill([
        'role' => $role,
        'status' => $status,
        'deactivated_at' => $status === 'active' ? null : now()->subDay(),
        'scalpels_issuer' => 'https://issuer.example.test',
        'scalpels_connection_id' => 'connection-fixture',
        'scalpels_id' => $subject,
        'membership_confirmed_at' => now()->subMinute(),
        'membership_checked_at' => now()->subMinute(),
        'membership_response_at' => now()->subMinute(),
        'managed_membership_status' => $status === 'active' ? 'active' : 'removed',
        'managed_membership_role' => $role,
        'managed_membership_generation' => 7,
        'managed_membership_roster_version' => $sequence,
        'managed_membership_response_sequence' => $sequence,
        'managed_membership_responded_at' => now()->subMinute()->toAtomString(),
    ])->save();

    return $user->refresh();
}

function p4aConfirmation(
    string $subject,
    string $membershipStatus,
    string $role,
    int $sequence = 20,
): ManagedAuthConfirmation {
    return new ManagedAuthConfirmation(
        $subject,
        $membershipStatus,
        'active',
        $role,
        $sequence,
        $sequence,
        new DateTimeImmutable('2026-09-11T12:00:00+00:00'),
    );
}

function p4aExchange(
    string $subject,
    string $membershipStatus,
    string $role,
    int $sequence = 20,
): ManagedAuthExchange {
    return new ManagedAuthExchange(
        $subject,
        'membership-'.$subject,
        $membershipStatus,
        'active',
        $role,
        'Authority '.$subject,
        $subject.'@example.test',
        true,
        $sequence,
        $sequence,
        new DateTimeImmutable('2026-09-11T12:00:00+00:00'),
    );
}

function p4aStatement(
    ?string $sentIncumbent,
    ManagedOwnershipSubject $owner,
    ?ManagedOwnershipSubject $seatedOwner,
    int $sequence = 30,
): ManagedOwnershipStatement {
    return new ManagedOwnershipStatement(
        $sentIncumbent,
        $owner,
        $seatedOwner,
        $sequence,
        $sequence,
        new DateTimeImmutable('2026-09-11T12:00:00+00:00'),
    );
}

/** @return array<string, list<array<string, mixed>>> */
function p4aProtectedState(): array
{
    $tables = [
        'users',
        'sessions',
        'password_reset_tokens',
        'invitations',
        'credentials',
        'bfc_authority',
        'bfc_managed_handoffs',
    ];
    $state = [];

    foreach ($tables as $table) {
        if (! Schema::hasTable($table)) {
            continue;
        }

        $rows = DB::table($table)->get()->map(static function (object $row): array {
            $attributes = (array) $row;
            ksort($attributes);

            return $attributes;
        })->all();
        usort($rows, static fn (array $a, array $b): int => json_encode($a) <=> json_encode($b));
        $state[$table] = $rows;
    }

    return $state;
}

function p4aSeedProtectedStores(User $user): void
{
    DB::table('sessions')->insert([
        'id' => 'ownership-session-'.$user->getKey(),
        'user_id' => $user->getKey(),
        'payload' => 'ownership snapshot',
        'last_activity' => now()->timestamp,
    ]);
    DB::table('password_reset_tokens')->insert([
        'email' => $user->email,
        'token' => hash('sha256', 'ownership-reset'),
        'created_at' => now(),
    ]);
    DB::table('invitations')->insert([
        'id' => (string) Str::uuid(),
        'email' => 'ownership-invite-'.$user->getKey().'@example.test',
        'token' => hash('sha256', 'ownership-invite-'.$user->getKey()),
        'invited_by' => (string) $user->getKey(),
        'role' => 'member',
        'expires_at' => now()->addDay(),
        'created_at' => now(),
        'updated_at' => now(),
    ]);
    Credential::query()->create([
        'kind' => CredentialKind::Bearer,
        'subject_type' => SubjectType::UserPrincipal,
        'subject_ref' => (string) $user->scalpels_id,
        'name' => 'ownership-credential-'.$user->getKey(),
        'user_id' => (string) $user->getKey(),
        'secret_hash' => hash('sha256', 'ownership-credential-'.$user->getKey()),
    ]);
}

it('sends and parses the typed O1 managed-transition-v1 exchange', function (): void {
    $fixture = p4aConfigureAuthority();
    $fixture->ownershipOverrides = [
        'owner' => ['scalpels_id' => 'wire-incoming', 'membership_status' => 'active', 'role' => 'owner'],
        'seated_owner' => ['scalpels_id' => 'wire-incumbent', 'membership_status' => 'disabled', 'role' => 'member'],
        'roster_version' => 41,
        'response_sequence' => 42,
        'responded_at' => '2026-09-11T12:00:00.123+00:00',
    ];

    $statement = app(ManagedAuthClient::class)->ownership(p4aConnection(), 'wire-incumbent');

    expect($fixture->calls)->toHaveCount(1)
        ->and($fixture->calls[0])->toBe([
            'method' => 'POST',
            'path' => '/managed-transition/v1/ownership',
            'body' => [
                'connection_id' => 'connection-fixture',
                'installation_id' => 'installation-fixture',
                'seated_owner_scalpels_id' => 'wire-incumbent',
            ],
        ])->and($statement->requestedSeatedOwnerScalpelsId)->toBe('wire-incumbent')
        ->and($statement->owner->scalpelsId)->toBe('wire-incoming')
        ->and($statement->owner->role)->toBe('owner')
        ->and($statement->seatedOwner?->membershipStatus)->toBe('disabled')
        ->and($statement->seatedOwner?->role)->toBe('member')
        ->and($statement->rosterVersion)->toBe(41)
        ->and($statement->responseSequence)->toBe(42);
});

it('refuses malformed O1 nested members before constructing a statement', function (
    string $member,
    string $field,
    mixed $value,
): void {
    $fixture = p4aConfigureAuthority();
    $fixture->ownershipOverrides = [
        'owner' => ['scalpels_id' => 'wire-incoming', 'membership_status' => 'active', 'role' => 'owner'],
        'seated_owner' => ['scalpels_id' => 'wire-incumbent', 'membership_status' => 'active', 'role' => 'admin'],
    ];
    $fixture->ownershipResponder = static function (array $request, array $payload) use ($member, $field, $value): mixed {
        if ($value === '__missing__') {
            unset($payload[$member][$field]);
        } else {
            $payload[$member][$field] = $value;
        }

        return Http::response($payload);
    };

    expect(fn (): ManagedOwnershipStatement => app(ManagedAuthClient::class)->ownership(
        p4aConnection(),
        'wire-incumbent',
    ))->toThrow(ManagedAuthRefused::class);
})->with([
    'missing incoming id' => ['owner', 'scalpels_id', '__missing__'],
    'null incoming id' => ['owner', 'scalpels_id', null],
    'mistyped incoming id' => ['owner', 'scalpels_id', 123],
    'oversized incoming id' => ['owner', 'scalpels_id', str_repeat('x', 256)],
    'unknown incoming role' => ['owner', 'role', 'super-owner'],
    'unknown incoming status' => ['owner', 'membership_status', 'paused'],
    'unknown seated role' => ['seated_owner', 'role', 'former-owner'],
    'unknown seated status' => ['seated_owner', 'membership_status', 'pending'],
]);

it('acquires a fresh managed Owner through the browser exchange and serves Owner and Admin authority', function (): void {
    CarbonImmutable::setTestNow('2026-09-11T12:00:00+00:00');
    $fixture = p4aConfigureAuthority();
    $fixture->exchangeOverrides = [
        'scalpels_id' => 'fresh-owner',
        'membership_id' => 'fresh-owner-membership',
        'role' => 'owner',
        'display_name' => 'Fresh Owner',
        'contact_email' => 'fresh-owner@example.test',
    ];
    Route::middleware(['web', 'bfc.auth'])->get('/p4a-owner-operation', static function (): string {
        abort_unless(request()->user()?->role === 'owner', 403);

        return 'owner operation';
    });
    Route::middleware(['web', 'bfc.admin'])->get('/p4a-admin-operation', static fn (): string => 'admin operation');
    Http::fake(fn (ClientRequest $request) => $fixture->respond($request));
    $begin = $this->get('/bfc/managed/login')->assertRedirect();
    $sessionId = session()->getId();
    $nonce = session(ManagedHandoff::SESSION_NONCE_KEY);
    parse_str((string) parse_url((string) $begin->headers->get('Location'), PHP_URL_QUERY), $query);

    $this->withSession([ManagedHandoff::SESSION_NONCE_KEY => $nonce])
        ->get('/bfc/managed/callback?'.http_build_query([
            'state' => $query['state'],
            'code' => 'fresh-owner-code',
        ]))
        ->assertRedirect('/');

    $owner = User::query()->where('scalpels_id', 'fresh-owner')->sole();
    expect($owner->role)->toBe('owner')
        ->and($owner->owner_slot)->toBe('owner')
        ->and(auth('web')->id())->toBe($owner->getKey())
        ->and(session()->getId())->not->toBe($sessionId)
        ->and(session(StandaloneAccess::SESSION_VERSION_KEY))->toBe($owner->auth_session_version);
    $this->get('/p4a-owner-operation')->assertOk()->assertSeeText('owner operation');
    $this->get('/p4a-admin-operation')->assertOk()->assertSeeText('admin operation');

    $member = p4aUser('fresh-member');
    $this->actingAsVersioned($member)->get('/p4a-owner-operation')->assertForbidden();
    $this->actingAsVersioned($member)->get('/p4a-admin-operation')->assertForbidden();
});

it('applies each distinct Part 1 ownership-table row', function (array $case): void {
    CarbonImmutable::setTestNow('2026-09-11T12:00:00+00:00');
    $fixture = p4aConfigureAuthority();
    $subjectId = 'table-subject';

    if ($case['relation'] === 'other') {
        p4aUser('table-incumbent', 'owner');
    }

    $subject = $case['exists']
        ? p4aUser($subjectId, $case['relation'] === 'subject' ? 'owner' : 'member')
        : null;

    if (in_array($case['outcome'], ['ownership_neutral_denial', 'owner_denied'], true)
        && $subject instanceof User) {
        p4aSeedProtectedStores($subject);
    }

    if ($case['refused']) {
        p4aSeedProtectedStores($subject ?? User::query()->whereNotNull('owner_slot')->sole());
        $before = p4aProtectedState();
        $fixture->ownershipResponder = static fn (): mixed => Http::response([
            'contract_version' => ManagedAuthClient::TRANSITION_CONTRACT_VERSION,
            'error' => 'unavailable',
        ], 503);
    }

    $apply = function () use ($case, $subject, $subjectId): bool|User|null {
        if ($case['leg'] === 'confirmation') {
            expect($subject)->toBeInstanceOf(User::class);

            return app(ManagedMembershipResponses::class)->applyConfirmation(
                p4aConnection(),
                $subject,
                p4aConfirmation($subjectId, $case['status'], $case['role']),
            );
        }

        return app(ManagedMembershipResponses::class)->applyExchange(
            p4aConnection(),
            p4aExchange($subjectId, $case['status'], $case['role']),
        );
    };

    if ($case['refused']) {
        expect($apply)->toThrow(ManagedAuthRefused::class, 'managed_owner_transition_refused')
            ->and(p4aProtectedState())->toBe($before);

        return;
    }

    $result = $apply();
    $subject = User::query()->where('scalpels_id', $subjectId)->first();
    expect($case['outcome'])->toBeString();

    match ($case['outcome']) {
        'owner_acquire' => expect($subject?->role)->toBe('owner'),
        'ownership_neutral' => expect($subject?->role)->toBe($case['role'])
            ->and(User::query()->whereNotNull('owner_slot')->count())->toBe($case['relation'] === 'other' ? 1 : 0),
        'ownership_neutral_denial' => expect($subject?->status)->toBe('inactive')
            ->and($subject?->role)->toBe('member')
            ->and($subject?->auth_session_version)->toBe(2)
            ->and(DB::table('sessions')->where('user_id', $subject?->getKey())->exists())->toBeFalse()
            ->and(DB::table('password_reset_tokens')->where('email', $subject?->email)->exists())->toBeFalse()
            ->and(DB::table('invitations')->where('invited_by', (string) $subject?->getKey())->value('cancelled_at'))->not->toBeNull()
            ->and(Credential::query()->where('user_id', (string) $subject?->getKey())->sole()->revoked_at)->not->toBeNull(),
        'ownership_absent_denial' => expect($result)->toBeNull()
            ->and($subject)->toBeNull(),
        'owner_reaffirm' => expect($subject?->role)->toBe('owner')
            ->and($subject?->managed_membership_response_sequence)->toBe(20),
        'owner_denied' => expect($subject?->status)->toBe('inactive')
            ->and($subject?->role)->toBe('owner')
            ->and($subject?->managed_membership_status)->toBe($case['status'])
            ->and($subject?->auth_session_version)->toBe(2)
            ->and(DB::table('sessions')->where('user_id', $subject?->getKey())->exists())->toBeFalse()
            ->and(DB::table('password_reset_tokens')->where('email', $subject?->email)->exists())->toBeFalse()
            ->and(DB::table('invitations')->where('invited_by', (string) $subject?->getKey())->value('cancelled_at'))->not->toBeNull()
            ->and(Credential::query()->where('user_id', (string) $subject?->getKey())->sole()->revoked_at)->not->toBeNull(),
    };
})->with([
    'owner_acquire' => [[
        'relation' => 'vacant', 'status' => 'active', 'role' => 'owner', 'leg' => 'confirmation',
        'exists' => true, 'outcome' => 'owner_acquire', 'refused' => false,
    ]],
    'ownership_neutral' => [[
        'relation' => 'vacant', 'status' => 'active', 'role' => 'admin', 'leg' => 'exchange',
        'exists' => true, 'outcome' => 'ownership_neutral', 'refused' => false,
    ]],
    'ownership_neutral_denial' => [[
        'relation' => 'vacant', 'status' => 'removed', 'role' => 'owner', 'leg' => 'confirmation',
        'exists' => true, 'outcome' => 'ownership_neutral_denial', 'refused' => false,
    ]],
    'ownership_absent_denial / vacant' => [[
        'relation' => 'vacant', 'status' => 'disabled', 'role' => 'owner', 'leg' => 'exchange',
        'exists' => false, 'outcome' => 'ownership_absent_denial', 'refused' => false,
    ]],
    'owner_reaffirm' => [[
        'relation' => 'subject', 'status' => 'active', 'role' => 'owner', 'leg' => 'exchange',
        'exists' => true, 'outcome' => 'owner_reaffirm', 'refused' => false,
    ]],
    'owner_contested / incumbent demotion' => [[
        'relation' => 'subject', 'status' => 'active', 'role' => 'admin', 'leg' => 'confirmation',
        'exists' => true, 'outcome' => 'owner_contested', 'refused' => true,
    ]],
    'owner_denied' => [[
        'relation' => 'subject', 'status' => 'disabled', 'role' => 'admin', 'leg' => 'exchange',
        'exists' => true, 'outcome' => 'owner_denied', 'refused' => false,
    ]],
    'owner_contested / different incoming Owner' => [[
        'relation' => 'other', 'status' => 'active', 'role' => 'owner', 'leg' => 'exchange',
        'exists' => true, 'outcome' => 'owner_contested', 'refused' => true,
    ]],
    'ownership_neutral / incumbent untouched' => [[
        'relation' => 'other', 'status' => 'active', 'role' => 'admin', 'leg' => 'confirmation',
        'exists' => true, 'outcome' => 'ownership_neutral', 'refused' => false,
    ]],
    'ownership_neutral_denial / incumbent untouched' => [[
        'relation' => 'other', 'status' => 'removed', 'role' => 'owner', 'leg' => 'exchange',
        'exists' => true, 'outcome' => 'ownership_neutral_denial', 'refused' => false,
    ]],
    'ownership_absent_denial / incumbent untouched' => [[
        'relation' => 'other', 'status' => 'disabled', 'role' => 'owner', 'leg' => 'exchange',
        'exists' => false, 'outcome' => 'ownership_absent_denial', 'refused' => false,
    ]],
]);

it('consumes confirmation subject binding before the ownership table', function (): void {
    p4aConfigureAuthority();
    $unpersisted = new User;
    $unpersisted->forceFill([
        'scalpels_issuer' => p4aConnection()->issuer,
        'scalpels_connection_id' => p4aConnection()->connectionId,
        'scalpels_id' => 'absent-confirmation',
    ]);
    $before = p4aProtectedState();

    expect(fn (): bool => app(ManagedMembershipResponses::class)->applyConfirmation(
        p4aConnection(),
        $unpersisted,
        p4aConfirmation('absent-confirmation', 'active', 'owner'),
    ))->toThrow(ManagedAuthRefused::class)
        ->and(p4aProtectedState())->toBe($before);
});

it('consumes unrecognized roles before the ownership table', function (): void {
    p4aConfigureAuthority();
    $subject = p4aUser('unrecognized-role', 'member');
    $before = p4aProtectedState();

    expect(fn (): bool => app(ManagedMembershipResponses::class)->applyConfirmation(
        p4aConnection(),
        $subject,
        p4aConfirmation('unrecognized-role', 'active', 'super-owner'),
    ))->toThrow(ManagedAuthRefused::class, 'managed_role_refused')
        ->and(p4aProtectedState())->toBe($before);
});

it('applies every valid O1 transfer cell and writes the incumbent role exactly as stated', function (
    string $incumbentRole,
    string $incumbentStatus,
): void {
    p4aConfigureAuthority();
    $incumbent = p4aUser('o1-incumbent', 'owner', 'inactive');
    $incoming = p4aUser('o1-incoming', 'member', 'inactive');
    p4aSeedProtectedStores($incumbent);
    $credential = Credential::query()->where('user_id', (string) $incumbent->getKey())->sole();
    $statement = p4aStatement(
        'o1-incumbent',
        new ManagedOwnershipSubject('o1-incoming', 'active', 'owner'),
        new ManagedOwnershipSubject('o1-incumbent', $incumbentStatus, $incumbentRole),
    );

    expect(app(ManagedMembershipResponses::class)->applyOwnershipStatement(p4aConnection(), $statement))->toBeTrue();
    $incumbent->refresh();
    $incoming->refresh();
    expect($incumbent->role)->toBe($incumbentRole)
        ->and($incumbent->status)->toBe($incumbentStatus === 'active' ? 'active' : 'inactive')
        ->and($incumbent->managed_membership_role)->toBe($incumbentRole)
        ->and($incumbent->managed_membership_status)->toBe($incumbentStatus)
        ->and($incoming->role)->toBe('owner')
        ->and($incoming->status)->toBe('active')
        ->and($incoming->managed_membership_role)->toBe('owner')
        ->and($incoming->managed_membership_status)->toBe('active')
        ->and($credential->refresh()->revoked_at !== null)->toBe($incumbentStatus !== 'active')
        ->and(DB::table('sessions')->where('user_id', $incumbent->getKey())->exists())->toBe($incumbentStatus === 'active')
        ->and(DB::table('password_reset_tokens')->where('email', $incumbent->email)->exists())->toBe($incumbentStatus === 'active')
        ->and(DB::table('invitations')->where('invited_by', (string) $incumbent->getKey())->value('cancelled_at') !== null)
        ->toBe($incumbentStatus !== 'active');
})->with([
    'active Admin' => ['admin', 'active'],
    'removed Admin' => ['admin', 'removed'],
    'disabled Admin' => ['admin', 'disabled'],
    'active Member' => ['member', 'active'],
    'removed Member' => ['member', 'removed'],
    'disabled Member' => ['member', 'disabled'],
]);

it('does not let a stale membership answer undo O1 denial or reactivation state', function (): void {
    p4aConfigureAuthority();
    $incumbent = p4aUser('o1-projection-incumbent', 'owner', 'active', 10);
    $incoming = p4aUser('o1-projection-incoming', 'member', 'inactive', 10);
    $responses = app(ManagedMembershipResponses::class);
    $statement = p4aStatement(
        'o1-projection-incumbent',
        new ManagedOwnershipSubject('o1-projection-incoming', 'active', 'owner'),
        new ManagedOwnershipSubject('o1-projection-incumbent', 'removed', 'member'),
        30,
    );

    expect($responses->applyOwnershipStatement(p4aConnection(), $statement))->toBeTrue()
        ->and($responses->applyExchange(
            p4aConnection(),
            p4aExchange('o1-projection-incumbent', 'active', 'member', 20),
        ))->toBeNull()
        ->and($incumbent->refresh()->status)->toBe('inactive')
        ->and($incumbent->managed_membership_status)->toBe('removed')
        ->and($incumbent->managed_membership_response_sequence)->toBe(30)
        ->and($incoming->refresh()->status)->toBe('active')
        ->and($incoming->managed_membership_status)->toBe('active')
        ->and($incoming->managed_membership_response_sequence)->toBe(30);
});

it('handles valid O1 acquisition, reaffirmation, and an absent incoming row without inference', function (string $case): void {
    p4aConfigureAuthority();
    $responses = app(ManagedMembershipResponses::class);

    if ($case === 'reaffirmation') {
        $owner = p4aUser('o1-reaffirm', 'owner', 'inactive');
        $statement = p4aStatement(
            'o1-reaffirm',
            new ManagedOwnershipSubject('o1-reaffirm', 'active', 'owner'),
            new ManagedOwnershipSubject('o1-reaffirm', 'active', 'owner'),
        );
    } else {
        $owner = $case === 'existing acquisition' ? p4aUser('o1-acquire') : null;
        $statement = p4aStatement(
            null,
            new ManagedOwnershipSubject('o1-acquire', 'active', 'owner'),
            null,
        );
    }

    expect($responses->applyOwnershipStatement(p4aConnection(), $statement))->toBeTrue();

    if ($case === 'absent acquisition') {
        expect(User::query()->where('scalpels_id', 'o1-acquire')->exists())->toBeFalse()
            ->and(User::query()->whereNotNull('owner_slot')->exists())->toBeFalse();
        $seated = $responses->applyExchange(p4aConnection(), p4aExchange('o1-acquire', 'active', 'owner', 40));
        expect($seated?->role)->toBe('owner');

        return;
    }

    expect($owner?->refresh()->role)->toBe('owner')
        ->and($owner?->status)->toBe('active');
})->with(['existing acquisition', 'absent acquisition', 'reaffirmation']);

it('refuses each terminal O1 consistency leaf with zero protected-state writes', function (ManagedOwnershipStatement $statement): void {
    p4aConfigureAuthority();
    $incumbent = p4aUser('o1-a', 'owner');
    p4aUser('o1-b');
    p4aUser('o1-c');
    p4aSeedProtectedStores($incumbent);
    $before = p4aProtectedState();

    expect(fn (): bool => app(ManagedMembershipResponses::class)->applyOwnershipStatement(
        p4aConnection(),
        $statement,
    ))->toThrow(ManagedAuthRefused::class)
        ->and(p4aProtectedState())->toBe($before);
})->with([
    'incoming role is not Owner' => [p4aStatement(
        'o1-a',
        new ManagedOwnershipSubject('o1-b', 'active', 'admin'),
        new ManagedOwnershipSubject('o1-a', 'active', 'member'),
    )],
    'incoming Owner is non-active' => [p4aStatement(
        'o1-a',
        new ManagedOwnershipSubject('o1-b', 'removed', 'owner'),
        new ManagedOwnershipSubject('o1-a', 'active', 'member'),
    )],
    'sent null with present seated Owner and different incoming Owner' => [p4aStatement(
        null,
        new ManagedOwnershipSubject('o1-b', 'active', 'owner'),
        new ManagedOwnershipSubject('o1-a', 'active', 'admin'),
    )],
    'sent incumbent with omitted seated Owner' => [p4aStatement(
        'o1-a',
        new ManagedOwnershipSubject('o1-b', 'active', 'owner'),
        null,
    )],
    'sent incumbent A with response seated B and incoming C' => [p4aStatement(
        'o1-a',
        new ManagedOwnershipSubject('o1-c', 'active', 'owner'),
        new ManagedOwnershipSubject('o1-b', 'active', 'member'),
    )],
    'equal IDs with conflicting objects' => [p4aStatement(
        'o1-a',
        new ManagedOwnershipSubject('o1-a', 'active', 'owner'),
        new ManagedOwnershipSubject('o1-a', 'active', 'admin'),
    )],
    'authority states two Owners' => [p4aStatement(
        'o1-a',
        new ManagedOwnershipSubject('o1-b', 'active', 'owner'),
        new ManagedOwnershipSubject('o1-a', 'active', 'owner'),
    )],
    'malformed incoming role' => [p4aStatement(
        'o1-a',
        new ManagedOwnershipSubject('o1-b', 'active', 'super-owner'),
        new ManagedOwnershipSubject('o1-a', 'active', 'member'),
    )],
    'malformed seated status' => [p4aStatement(
        'o1-a',
        new ManagedOwnershipSubject('o1-b', 'active', 'owner'),
        new ManagedOwnershipSubject('o1-a', 'paused', 'member'),
    )],
]);

it('refuses O1 when the seated Owner moved after the request and when the statement is older or equal', function (string $case): void {
    p4aConfigureAuthority();
    $incumbent = p4aUser('o1-race-a', 'owner');
    p4aUser('o1-race-b');
    $statement = p4aStatement(
        'o1-race-a',
        new ManagedOwnershipSubject('o1-race-b', 'active', 'owner'),
        new ManagedOwnershipSubject('o1-race-a', 'active', 'member'),
        30,
    );

    if ($case === 'moved') {
        $incumbent->forceFill(['role' => 'member'])->save();
        p4aUser('o1-race-c', 'owner');
    } else {
        DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
            'managed_ownership_generation' => 7,
            'managed_ownership_roster_version' => 30,
            'managed_ownership_response_sequence' => $case === 'older' ? 31 : 30,
        ]);
    }
    $before = p4aProtectedState();

    if ($case === 'moved') {
        expect(fn (): bool => app(ManagedMembershipResponses::class)->applyOwnershipStatement(
            p4aConnection(),
            $statement,
        ))->toThrow(ManagedAuthRefused::class);
    } else {
        expect(app(ManagedMembershipResponses::class)->applyOwnershipStatement(
            p4aConnection(),
            $statement,
        ))->toBeFalse();
    }
    expect(p4aProtectedState())->toBe($before);
})->with(['moved', 'older', 'equal']);

it('drives the owner_contested exchange through one O1 pull and re-evaluates the same browser login', function (): void {
    CarbonImmutable::setTestNow('2026-09-11T12:00:00+00:00');
    $fixture = p4aConfigureAuthority();
    $incumbent = p4aUser('recover-incumbent', 'owner');
    p4aSeedProtectedStores($incumbent);
    expect(app(ManagedMembershipResponses::class)->applyConfirmation(
        p4aConnection(),
        $incumbent,
        p4aConfirmation('recover-incumbent', 'removed', 'member', 20),
    ))->toBeFalse();
    $incoming = p4aUser('subject-fixture', 'member', 'inactive', 1);
    $fixture->exchangeOverrides = ['role' => 'owner'];
    $fixture->ownershipOverrides = [
        'owner' => ['scalpels_id' => 'subject-fixture', 'membership_status' => 'active', 'role' => 'owner'],
        'seated_owner' => ['scalpels_id' => 'recover-incumbent', 'membership_status' => 'active', 'role' => 'admin'],
    ];
    $begin = $this->get('/bfc/managed/login')->assertRedirect();
    $nonce = session(ManagedHandoff::SESSION_NONCE_KEY);
    parse_str((string) parse_url((string) $begin->headers->get('Location'), PHP_URL_QUERY), $query);

    $this->withSession([ManagedHandoff::SESSION_NONCE_KEY => $nonce])
        ->get('/bfc/managed/callback?'.http_build_query(['state' => $query['state'], 'code' => 'recovery-code']))
        ->assertRedirect('/');

    expect(array_column($fixture->calls, 'path'))->toBe([
        '/managed-auth/v1/handoffs',
        '/managed-auth/v1/handoffs/'.$query['state'].'/exchange',
        '/managed-transition/v1/ownership',
    ])->and($incumbent->refresh()->role)->toBe('admin')
        ->and($incumbent->status)->toBe('active')
        ->and($incoming->refresh()->role)->toBe('owner')
        ->and($incoming->status)->toBe('active')
        ->and(auth('web')->id())->toBe($incoming->getKey());
});

it('keeps contested login fail-closed after each invalid O1 direction and pulls only once', function (string $case): void {
    $fixture = p4aConfigureAuthority();
    $incumbent = p4aUser('trigger-incumbent', 'owner');
    $candidate = p4aUser('trigger-candidate');
    p4aSeedProtectedStores($incumbent);

    if ($case === 'older') {
        DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
            'managed_ownership_generation' => 7,
            'managed_ownership_roster_version' => 50,
            'managed_ownership_response_sequence' => 50,
        ]);
    }

    $fixture->ownershipOverrides = [
        'owner' => ['scalpels_id' => 'trigger-candidate', 'membership_status' => 'active', 'role' => 'owner'],
        'seated_owner' => ['scalpels_id' => 'trigger-incumbent', 'membership_status' => 'active', 'role' => 'admin'],
    ];
    $fixture->ownershipResponder = match ($case) {
        'unavailable' => static fn (): mixed => Http::response([
            'contract_version' => ManagedAuthClient::TRANSITION_CONTRACT_VERSION,
            'error' => 'unavailable',
        ], 503),
        'malformed' => static function (array $request, array $payload): mixed {
            unset($payload['owner']['role']);

            return Http::response($payload);
        },
        'refused' => static function (array $request, array $payload): mixed {
            $payload['seated_owner']['role'] = 'owner';

            return Http::response($payload);
        },
        default => null,
    };
    $before = p4aProtectedState();

    expect(fn (): ?User => app(ManagedMembershipResponses::class)->applyExchange(
        p4aConnection(),
        p4aExchange('trigger-candidate', 'active', 'owner'),
    ))->toThrow(ManagedAuthRefused::class, 'managed_owner_transition_refused')
        ->and(p4aProtectedState())->toBe($before)
        ->and(array_column($fixture->calls, 'path'))->toBe(['/managed-transition/v1/ownership'])
        ->and($candidate->fresh()->role)->toBe('member');
})->with(['unavailable', 'malformed', 'older', 'refused']);

it('does not pull O1 from confirmation, non-Owner answers, or non-active answers', function (string $case): void {
    $fixture = p4aConfigureAuthority();
    $owner = p4aUser('no-pull-owner', 'owner');
    $subject = p4aUser('no-pull-subject');
    $responses = app(ManagedMembershipResponses::class);

    if ($case === 'confirmation') {
        expect(fn (): bool => $responses->applyConfirmation(
            p4aConnection(),
            $subject,
            p4aConfirmation('no-pull-subject', 'active', 'owner'),
        ))->toThrow(ManagedAuthRefused::class, 'managed_owner_transition_refused');
    } elseif ($case === 'non-Owner') {
        expect($responses->applyExchange(
            p4aConnection(),
            p4aExchange('no-pull-subject', 'active', 'admin'),
        )?->role)->toBe('admin');
    } else {
        expect($responses->applyExchange(
            p4aConnection(),
            p4aExchange('no-pull-subject', 'removed', 'owner'),
        ))->toBeNull();
    }

    expect($fixture->calls)->toBe([])
        ->and($owner->fresh()->role)->toBe('owner');
})->with(['confirmation', 'non-Owner', 'non-active']);

// The frozen contract says owner_contested is "REFUSED ... logged". Zero-writes was enforced; the audit half
// was not, so deleting the Log::warning call left the whole ownership suite green. Both P4a independents
// found that independently.
it('emits the audit warning when it refuses an owner_contested answer', function (): void {
    CarbonImmutable::setTestNow('2026-09-10T12:00:00+00:00');
    p4aConfigureAuthority();
    Log::spy();
    $seated = p4aUser('seated-owner', 'owner');
    $subject = p4aUser('contesting-subject', 'member');

    expect(fn (): bool => app(ManagedMembershipResponses::class)->applyConfirmation(
        p4aConnection(),
        $subject,
        p4aConfirmation('contesting-subject', 'active', 'owner', 20),
    ))->toThrow(ManagedAuthRefused::class);

    Log::shouldHaveReceived('warning')
        ->once()
        ->withArgs(static fn (string $message, array $context): bool => $message === 'Built for Cloud refused a managed response that would change the Owner.'
            && $context['reason_code'] === 'managed_owner_transition_refused'
            && $context['scalpels_id'] === 'contesting-subject');
});
