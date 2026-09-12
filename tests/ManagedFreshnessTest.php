<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\Auth\CredentialGuard;
use ArtisanBuild\BuiltForCloud\Auth\CredentialResolver;
use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureDashboardCredential;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\ManagedAuthConfirmation;
use ArtisanBuild\BuiltForCloud\ManagedAuthConnection;
use ArtisanBuild\BuiltForCloud\ManagedAuthExchange;
use ArtisanBuild\BuiltForCloud\ManagedFreshness;
use ArtisanBuild\BuiltForCloud\ManagedHandoff;
use ArtisanBuild\BuiltForCloud\ManagedMembershipResponses;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\StandaloneAccess;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\ManagedAuthorityFixture;
use ArtisanBuild\BuiltForCloud\User;
use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;

uses(RefreshDatabase::class);

function p3cConnection(): ManagedAuthConnection
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

function p3cConfigureAuthority(): ManagedAuthorityFixture
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
    config(['built-for-cloud.managed.client_secret' => 'fixture-client-secret']);
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

function p3cConfigureCredentialGuard(): void
{
    config([
        'auth.guards.bfc' => ['driver' => 'bfc', 'provider' => 'users'],
        'auth.providers.users' => ['driver' => 'eloquent', 'model' => User::class],
        'built-for-cloud.credentials.guard' => 'bfc',
    ]);
    app('auth')->forgetGuards();
}

function p3cUser(
    string $subject = 'subject-fixture',
    string $role = 'member',
    int $sequence = 13,
): User {
    $user = User::query()->create([
        'name' => $subject,
        'email' => $subject.'@example.test',
    ]);
    $user->forceFill([
        'role' => $role,
        'status' => 'active',
        'scalpels_issuer' => 'https://issuer.example.test',
        'scalpels_connection_id' => 'connection-fixture',
        'scalpels_id' => $subject,
        'membership_confirmed_at' => now(),
        'membership_checked_at' => now(),
        'membership_response_at' => now(),
        'managed_membership_status' => 'active',
        'managed_membership_role' => $role,
        'managed_membership_generation' => 7,
        'managed_membership_roster_version' => $sequence,
        'managed_membership_response_sequence' => $sequence,
        'managed_membership_responded_at' => now(),
    ])->save();

    return $user->refresh();
}

function p3cConfirmation(
    User $user,
    int $sequence,
    string $membershipStatus = 'active',
    string $connectionStatus = 'active',
    string $role = 'member',
    string $respondedAt = '2026-09-10T12:00:00+00:00',
    ?int $rosterVersion = null,
): ManagedAuthConfirmation {
    return new ManagedAuthConfirmation(
        (string) $user->scalpels_id,
        $membershipStatus,
        $connectionStatus,
        $role,
        $rosterVersion ?? $sequence,
        $sequence,
        new DateTimeImmutable($respondedAt),
    );
}

function p3cConfirmationCalls(ManagedAuthorityFixture $fixture): int
{
    return count(array_filter(
        $fixture->calls,
        static fn (array $call): bool => $call['path'] === '/managed-auth/v1/memberships/confirm',
    ));
}

/** @param list<string>|null $abilities */
function p3cAccountCredential(
    User $user,
    string $secret,
    CredentialKind $kind = CredentialKind::Bearer,
    SubjectType $subjectType = SubjectType::UserPrincipal,
    ?array $abilities = null,
): Credential {
    return Credential::query()->create([
        'kind' => $kind,
        'subject_type' => $subjectType,
        'subject_ref' => (string) $user->scalpels_id,
        'name' => 'account-'.$user->scalpels_id,
        'user_id' => (string) $user->getKey(),
        'abilities' => $abilities,
        'secret_hash' => hash('sha256', $secret),
    ]);
}

function p3cDeploymentCredential(User $creator, string $secret): Credential
{
    $credential = Credential::query()->create([
        'kind' => CredentialKind::Bearer,
        'subject_type' => SubjectType::Installation,
        'subject_ref' => 'installation-fixture',
        'name' => 'deployment',
        'secret_hash' => hash('sha256', $secret),
    ]);

    DB::transaction(static fn (): CredentialAuditEvent => app(LifecycleEventRecorder::class)->record(
        event: LifecycleEventType::Issued,
        credentialId: $credential->id,
        actor: AuditActor::boundUser((string) $creator->getKey()),
        drainAfterCommit: false,
    ));

    return $credential;
}

function p3cSession(User $user, string $id): void
{
    DB::table('sessions')->insert([
        'id' => $id,
        'user_id' => $user->getKey(),
        'payload' => 'managed freshness test',
        'last_activity' => now()->getTimestamp(),
    ]);
}

it('serves stored state at 299 seconds and calls the authority at exactly 300 seconds', function (): void {
    CarbonImmutable::setTestNow('2026-09-10T12:00:00+00:00');
    $fixture = p3cConfigureAuthority();
    $user = p3cUser();
    $freshness = app(ManagedFreshness::class);

    CarbonImmutable::setTestNow('2026-09-10T12:04:59+00:00');
    expect($freshness->allows($user))->toBeTrue()
        ->and(p3cConfirmationCalls($fixture))->toBe(0);

    CarbonImmutable::setTestNow('2026-09-10T12:05:00+00:00');
    expect($freshness->allows($user))->toBeTrue()
        ->and(p3cConfirmationCalls($fixture))->toBe(1)
        ->and($user->fresh()->membership_confirmed_at?->toAtomString())->toBe(now()->toAtomString());
});

it('authenticates two consecutive managed logins with one unchanged authority payload without advancing confirmation', function (): void {
    CarbonImmutable::setTestNow('2026-09-10T12:00:00+00:00');
    $fixture = p3cConfigureAuthority();
    $login = function (string $code) {
        $entry = $this->get('/bfc/managed/login')->assertRedirect();
        parse_str((string) parse_url((string) $entry->headers->get('Location'), PHP_URL_QUERY), $query);

        return $this->withSession([
            ManagedHandoff::SESSION_NONCE_KEY => session(ManagedHandoff::SESSION_NONCE_KEY),
        ])->get('/bfc/managed/callback?'.http_build_query([
            'state' => $query['state'],
            'code' => $code,
        ]));
    };

    $login('first-login-code')->assertRedirect('/');
    $user = User::query()->where('scalpels_id', 'subject-fixture')->sole();
    $firstConfirmation = $user->membership_confirmed_at?->toAtomString();
    auth('web')->logout();

    CarbonImmutable::setTestNow('2026-09-10T12:01:00+00:00');
    $login('second-login-code')->assertRedirect('/');

    expect(auth('web')->id())->toBe($user->getKey())
        ->and(User::query()->where('scalpels_id', 'subject-fixture')->count())->toBe(1)
        ->and($user->fresh()->membership_confirmed_at?->toAtomString())->toBe($firstConfirmation)
        ->and($user->fresh()->managed_membership_response_sequence)->toBe(13)
        ->and(count(array_filter(
            $fixture->calls,
            static fn (array $call): bool => str_contains($call['path'], '/exchange'),
        )))->toBe(2);
});

it('allows a duplicate confirmation from stored active grace without advancing confirmation', function (): void {
    CarbonImmutable::setTestNow('2026-09-10T12:00:00+00:00');
    $fixture = p3cConfigureAuthority();
    $user = p3cUser();
    $confirmedAt = $user->membership_confirmed_at?->toAtomString();
    DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
        'managed_connection_status' => 'active',
        'managed_connection_generation' => 7,
        'managed_connection_roster_version' => 13,
        'managed_connection_response_sequence' => 13,
    ]);
    $fixture->confirmationOverrides = [
        'roster_version' => 13,
        'response_sequence' => 13,
    ];

    CarbonImmutable::setTestNow('2026-09-10T12:05:00+00:00');
    expect(app(ManagedFreshness::class)->allows($user))->toBeTrue()
        ->and(p3cConfirmationCalls($fixture))->toBe(1)
        ->and($user->fresh()->membership_confirmed_at?->toAtomString())->toBe($confirmedAt)
        ->and($user->fresh()->managed_membership_response_sequence)->toBe(13);
});

it('records the exact per-outcome freshness timestamps without letting denial or failure confirm', function (): void {
    CarbonImmutable::setTestNow('2026-09-10T12:00:00+00:00');
    $fixture = p3cConfigureAuthority();
    $freshness = app(ManagedFreshness::class);
    $denied = p3cUser('denied-subject');
    $malformed = p3cUser('malformed-subject');
    $failed = p3cUser('failed-subject');
    $fixture->confirmationResponder = static function (array $request, array $payload): mixed {
        return match ($request['scalpels_id']) {
            'denied-subject' => Http::response(array_merge($payload, ['membership_status' => 'removed'])),
            'malformed-subject' => Http::response(array_diff_key($payload, ['role' => true])),
            default => Http::response([
                'contract_version' => 'managed-auth-v1',
                'error' => 'server_error',
            ], 503),
        };
    };

    CarbonImmutable::setTestNow('2026-09-10T12:05:00+00:00');
    expect($freshness->allows($denied))->toBeFalse()
        ->and($freshness->allows($malformed))->toBeTrue()
        ->and($freshness->allows($failed))->toBeTrue();

    $denied->refresh();
    $malformed->refresh();
    $failed->refresh();
    expect($denied->membership_confirmed_at?->toAtomString())->toBe('2026-09-10T12:00:00+00:00')
        ->and($denied->membership_checked_at?->toAtomString())->toBe(now()->toAtomString())
        ->and($denied->membership_response_at?->toAtomString())->toBe(now()->toAtomString())
        ->and($malformed->membership_confirmed_at?->toAtomString())->toBe('2026-09-10T12:00:00+00:00')
        ->and($malformed->membership_checked_at?->toAtomString())->toBe(now()->toAtomString())
        ->and($malformed->membership_response_at?->toAtomString())->toBe('2026-09-10T12:00:00+00:00')
        ->and($failed->membership_confirmed_at?->toAtomString())->toBe('2026-09-10T12:00:00+00:00')
        ->and($failed->membership_checked_at?->toAtomString())->toBe(now()->toAtomString())
        ->and($failed->membership_response_at?->toAtomString())->toBe('2026-09-10T12:00:00+00:00');
});

it('honours Retry-After beyond the minimum suppression and caps it at 300 seconds', function (): void {
    CarbonImmutable::setTestNow('2026-09-10T12:00:00+00:00');
    $fixture = p3cConfigureAuthority();
    $user = p3cUser();
    $freshness = app(ManagedFreshness::class);
    $fixture->confirmationResponder = static fn (): mixed => Http::response([
        'contract_version' => 'managed-auth-v1',
        'error' => 'rate_limited',
    ], 429, ['Retry-After' => '999']);

    CarbonImmutable::setTestNow('2026-09-10T12:05:00+00:00');
    expect($freshness->allows($user))->toBeTrue();
    CarbonImmutable::setTestNow('2026-09-10T12:09:59+00:00');
    expect($freshness->allows($user))->toBeTrue()
        ->and(p3cConfirmationCalls($fixture))->toBe(1);
    CarbonImmutable::setTestNow('2026-09-10T12:10:00+00:00');
    expect($freshness->allows($user))->toBeTrue()
        ->and(p3cConfirmationCalls($fixture))->toBe(2);
});

it('suppresses another attempt for at least 30 seconds when Retry-After is shorter', function (): void {
    CarbonImmutable::setTestNow('2026-09-10T12:00:00+00:00');
    $fixture = p3cConfigureAuthority();
    $user = p3cUser();
    $freshness = app(ManagedFreshness::class);
    $fixture->confirmationResponder = static fn (): mixed => Http::response([
        'contract_version' => 'managed-auth-v1',
        'error' => 'rate_limited',
    ], 429, ['Retry-After' => '5']);

    CarbonImmutable::setTestNow('2026-09-10T12:05:00+00:00');
    expect($freshness->allows($user))->toBeTrue();
    CarbonImmutable::setTestNow('2026-09-10T12:05:29+00:00');
    expect($freshness->allows($user))->toBeTrue()
        ->and(p3cConfirmationCalls($fixture))->toBe(1);
    CarbonImmutable::setTestNow('2026-09-10T12:05:30+00:00');
    expect($freshness->allows($user))->toBeTrue()
        ->and(p3cConfirmationCalls($fixture))->toBe(2);
});

it('keeps membership and connection high-water marks independent across subjects in both arrival orders', function (array $order, string $case): void {
    CarbonImmutable::setTestNow('2026-09-10T12:00:00+00:00');
    p3cConfigureAuthority();
    $a = p3cUser('subject-a', sequence: 10);
    $b = p3cUser('subject-b', sequence: 10);
    DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
        'managed_connection_status' => 'active',
        'managed_connection_generation' => 7,
        'managed_connection_roster_version' => 10,
        'managed_connection_response_sequence' => 10,
    ]);
    $responses = app(ManagedMembershipResponses::class);
    $incoming = $case === 'membership'
        ? [
            'a' => p3cConfirmation($a, 20, membershipStatus: 'removed'),
            'b' => p3cConfirmation($b, 21),
        ]
        : [
            'a' => p3cConfirmation($a, 20, connectionStatus: 'inactive'),
            'b' => p3cConfirmation($b, 21),
        ];

    foreach ($order as $subject) {
        $responses->applyConfirmation(p3cConnection(), $subject === 'a' ? $a : $b, $incoming[$subject]);
    }

    $authority = DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->first();
    expect($a->fresh()->managed_membership_status)->toBe($case === 'membership' ? 'removed' : 'active')
        ->and($a->fresh()->managed_membership_response_sequence)->toBe(20)
        ->and($b->fresh()->managed_membership_status)->toBe('active')
        ->and($b->fresh()->managed_membership_response_sequence)->toBe(21)
        ->and($authority->managed_connection_status)->toBe('active')
        ->and($authority->managed_connection_response_sequence)->toBe(21);
})->with([
    'membership A then B' => [['a', 'b'], 'membership'],
    'membership B then A' => [['b', 'a'], 'membership'],
    'connection A then B' => [['a', 'b'], 'connection'],
    'connection B then A' => [['b', 'a'], 'connection'],
]);

it('does not let an absurd future responded_at suppress a later current denial', function (): void {
    CarbonImmutable::setTestNow('2026-09-10T12:00:00+00:00');
    p3cConfigureAuthority();
    $user = p3cUser(sequence: 10);
    $responses = app(ManagedMembershipResponses::class);

    $responses->applyConfirmation(
        p3cConnection(),
        $user,
        p3cConfirmation($user, 20, respondedAt: '9999-12-31T23:59:59+00:00'),
    );
    CarbonImmutable::setTestNow('2026-09-10T12:01:00+00:00');
    $responses->applyConfirmation(
        p3cConnection(),
        $user,
        p3cConfirmation($user, 21, membershipStatus: 'removed', respondedAt: '2026-09-10T12:01:00+00:00'),
    );

    expect($user->fresh()->managed_membership_status)->toBe('removed')
        ->and($user->fresh()->managed_membership_response_sequence)->toBe(21)
        ->and($user->fresh()->membership_confirmed_at?->toAtomString())->toBe('2026-09-10T12:00:00+00:00');
});

it('does not let duplicate older or lower-roster answers advance or revive membership state', function (): void {
    CarbonImmutable::setTestNow('2026-09-10T12:00:00+00:00');
    p3cConfigureAuthority();
    $user = p3cUser(sequence: 10);
    $responses = app(ManagedMembershipResponses::class);

    $responses->applyConfirmation(
        p3cConnection(),
        $user,
        p3cConfirmation($user, 20, role: 'admin'),
    );
    $confirmedAt = $user->fresh()->membership_confirmed_at?->toAtomString();
    CarbonImmutable::setTestNow('2026-09-10T12:01:00+00:00');
    $responses->applyConfirmation(
        p3cConnection(),
        $user,
        p3cConfirmation($user, 20, role: 'owner'),
    );
    $responses->applyConfirmation(
        p3cConnection(),
        $user,
        p3cConfirmation($user, 21, role: 'owner', rosterVersion: 19),
    );
    $responses->applyConfirmation(
        p3cConnection(),
        $user,
        p3cConfirmation($user, 21, membershipStatus: 'removed'),
    );
    CarbonImmutable::setTestNow('2026-09-10T12:02:00+00:00');
    $allowed = $responses->applyConfirmation(p3cConnection(), $user, p3cConfirmation($user, 20));

    expect($allowed)->toBeFalse()
        ->and($user->fresh()->managed_membership_status)->toBe('removed')
        ->and($user->fresh()->managed_membership_role)->toBe('admin')
        ->and($user->fresh()->managed_membership_roster_version)->toBe(21)
        ->and($user->fresh()->managed_membership_response_sequence)->toBe(21)
        ->and($user->fresh()->membership_confirmed_at?->toAtomString())->toBe($confirmedAt);
});

it('preserves the stored role dimension while applying an accepted membership denial', function (
    string $leg,
    string $membershipStatus,
): void {
    CarbonImmutable::setTestNow('2026-09-10T12:05:00+00:00');
    p3cConfigureAuthority();
    $user = p3cUser('denied-role-subject', 'admin', 10);
    $accountCredential = p3cAccountCredential($user, 'denied-role-account-secret');
    $deploymentCredential = p3cDeploymentCredential($user, 'denied-role-deployment-secret');
    p3cSession($user, 'denied-role-session');
    $responses = app(ManagedMembershipResponses::class);
    $apply = static function (int $sequence, string $status) use ($leg, $responses, $user): bool|User|null {
        $respondedAt = $sequence === 20
            ? '2026-09-10T12:04:00+00:00'
            : '2026-09-10T12:03:00+00:00';

        if ($leg === 'confirmation') {
            return $responses->applyConfirmation(
                p3cConnection(),
                $user,
                p3cConfirmation($user, $sequence, membershipStatus: $status, respondedAt: $respondedAt),
            );
        }

        return $responses->applyExchange(p3cConnection(), new ManagedAuthExchange(
            'denied-role-subject',
            'denied-role-membership',
            $status,
            'active',
            'member',
            'Denied Role Subject',
            'denied-role-subject@example.test',
            true,
            $sequence,
            $sequence,
            new DateTimeImmutable($respondedAt),
        ));
    };

    $result = $apply(20, $membershipStatus);
    $denied = $user->fresh();

    expect($result)->toBe($leg === 'confirmation' ? false : null)
        ->and($denied->role)->toBe('admin')
        ->and($denied->managed_membership_role)->toBe('admin')
        ->and($denied->status)->toBe('inactive')
        ->and($denied->deactivated_at?->toAtomString())->toBe('2026-09-10T12:05:00+00:00')
        ->and($denied->managed_membership_status)->toBe($membershipStatus)
        ->and($denied->managed_membership_generation)->toBe(7)
        ->and($denied->managed_membership_roster_version)->toBe(20)
        ->and($denied->managed_membership_response_sequence)->toBe(20)
        ->and($denied->managed_membership_responded_at)->toBe('2026-09-10T12:04:00.000+00:00')
        ->and($denied->auth_session_version)->toBe(2)
        ->and($accountCredential->refresh()->revoked_at)->not->toBeNull()
        ->and($deploymentCredential->refresh()->revoked_at)->toBeNull()
        ->and(DB::table('sessions')->where('id', 'denied-role-session')->exists())->toBeFalse();

    $olderResult = $apply(19, 'active');

    expect($olderResult)->toBe($leg === 'confirmation' ? false : null)
        ->and($user->fresh()->status)->toBe('inactive')
        ->and($user->fresh()->managed_membership_status)->toBe($membershipStatus)
        ->and($user->fresh()->managed_membership_response_sequence)->toBe(20);
})->with([
    'confirmation / removed' => ['confirmation', 'removed'],
    'confirmation / disabled' => ['confirmation', 'disabled'],
    'exchange / removed' => ['exchange', 'removed'],
    'exchange / disabled' => ['exchange', 'disabled'],
]);

it('preserves managed_membership_role independently of users.role on an accepted denial', function (): void {
    p3cConfigureAuthority();
    $user = p3cUser('managed-role-discriminator', 'admin', 10);

    app(ManagedMembershipResponses::class)->applyConfirmation(
        p3cConnection(),
        $user,
        p3cConfirmation($user, 20, membershipStatus: 'removed', role: 'member'),
    );

    // This separate test prevents a users.role failure from masking this column.
    expect($user->fresh()->managed_membership_role)->toBe('admin');
});

it('writes an active answer role into both role columns and the next authorization decision', function (): void {
    CarbonImmutable::setTestNow('2026-09-10T12:00:00+00:00');
    p3cConfigureAuthority();
    $user = p3cUser('active-role-subject', 'admin', 10);
    Route::middleware(['web', 'bfc.admin'])->get('/active-role-decision', static fn (): string => 'authorized');

    $this->actingAsVersioned($user)->get('/active-role-decision')->assertOk();
    expect(app(ManagedMembershipResponses::class)->applyConfirmation(
        p3cConnection(),
        $user,
        p3cConfirmation($user, 20, role: 'member'),
    ))->toBeTrue()
        ->and($user->fresh()->role)->toBe('member')
        ->and($user->fresh()->managed_membership_role)->toBe('member');
    $this->actingAsVersioned($user->fresh())->get('/active-role-decision')->assertForbidden();
});

it('accepts lower order counters only when the current authority generation advances', function (): void {
    CarbonImmutable::setTestNow('2026-09-10T12:00:00+00:00');
    p3cConfigureAuthority();
    $user = p3cUser(sequence: 100);
    DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
        'generation' => 8,
        'managed_connection_status' => 'active',
        'managed_connection_generation' => 7,
        'managed_connection_roster_version' => 100,
        'managed_connection_response_sequence' => 100,
    ]);
    $connection = new ManagedAuthConnection(
        'https://issuer.example.test',
        'connection-fixture',
        'organization-fixture',
        'installation-fixture',
        8,
        'https://authority.example.test',
        'fixture-client-secret',
        null,
    );
    $response = new ManagedAuthConfirmation(
        'subject-fixture',
        'active',
        'active',
        'admin',
        1,
        1,
        new DateTimeImmutable('2026-09-10T12:00:00+00:00'),
    );

    expect(app(ManagedMembershipResponses::class)->applyConfirmation($connection, $user, $response))->toBeTrue();
    $authority = DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->first();
    expect($user->fresh()->managed_membership_generation)->toBe(8)
        ->and($user->fresh()->managed_membership_response_sequence)->toBe(1)
        ->and($authority->managed_connection_generation)->toBe(8)
        ->and($authority->managed_connection_response_sequence)->toBe(1);
});

it('applies a non-active callback denial without running the active upsert or revoking deployment credentials', function (): void {
    CarbonImmutable::setTestNow('2026-09-10T12:00:00+00:00');
    p3cConfigureAuthority();
    $user = p3cUser(sequence: 10);
    $accountCredential = p3cAccountCredential($user, 'callback-account-secret');
    $deploymentCredential = p3cDeploymentCredential($user, 'callback-deployment-secret');
    p3cSession($user, 'callback-session');
    $beforeConfirmed = $user->membership_confirmed_at?->toAtomString();
    CarbonImmutable::setTestNow('2026-09-10T12:05:00+00:00');
    $result = app(ManagedMembershipResponses::class)->applyExchange(
        p3cConnection(),
        new ManagedAuthExchange(
            'subject-fixture',
            'membership-fixture',
            'removed',
            'active',
            'admin',
            'Changed Name',
            'changed@example.test',
            true,
            14,
            14,
            new DateTimeImmutable('2026-09-10T12:05:00+00:00'),
        ),
    );

    $user->refresh();
    expect($result)->toBeNull()
        ->and($user->status)->toBe('inactive')
        ->and($user->deactivated_at)->not->toBeNull()
        ->and($user->auth_session_version)->toBe(2)
        ->and($user->role)->toBe('member')
        ->and($user->name)->toBe('subject-fixture')
        ->and($user->original_contact_email)->toBeNull()
        ->and($user->managed_membership_status)->toBe('removed')
        ->and($user->membership_confirmed_at?->toAtomString())->toBe($beforeConfirmed)
        ->and($user->membership_checked_at?->toAtomString())->toBe(now()->toAtomString())
        ->and($user->membership_response_at?->toAtomString())->toBe(now()->toAtomString())
        ->and($accountCredential->refresh()->revoked_at)->not->toBeNull()
        ->and($deploymentCredential->refresh()->revoked_at)->toBeNull()
        ->and(DB::table('sessions')->where('id', 'callback-session')->exists())->toBeFalse();
});

it('links the 299 300 and reset 1799 1800 boundaries on one clock including one managed-valid Admin operation', function (): void {
    CarbonImmutable::setTestNow('2026-09-10T12:00:00+00:00');
    $fixture = p3cConfigureAuthority();
    $member = p3cUser('timeline-member', 'member');
    $admin = p3cUser('timeline-admin', 'admin');
    $owner = p3cUser('timeline-owner', 'owner');
    $freshness = app(ManagedFreshness::class);
    $failure = true;
    $fixture->confirmationResponder = static function (array $request, array $payload) use (&$failure): mixed {
        if ($failure) {
            return Http::response([
                'contract_version' => 'managed-auth-v1',
                'error' => 'server_error',
            ], 503);
        }

        return Http::response(array_merge($payload, [
            'role' => $request['scalpels_id'] === 'timeline-admin' ? 'admin' : 'member',
        ]));
    };
    Route::middleware('web')->get('/thin-host/admin-operation', function (Request $request, ManagedFreshness $decision) {
        $user = $request->user();
        $allowedRole = $user instanceof User && in_array($user->role, ['owner', 'admin'], true);

        return $allowedRole && $decision->allows($user)
            ? response('managed admin operation')
            : response('Forbidden', 403);
    });

    CarbonImmutable::setTestNow('2026-09-10T12:04:59+00:00');
    expect($freshness->allows($member))->toBeTrue()
        ->and($freshness->allows($owner))->toBeTrue()
        ->and(p3cConfirmationCalls($fixture))->toBe(0);

    CarbonImmutable::setTestNow('2026-09-10T12:05:00+00:00');
    expect($freshness->allows($member))->toBeTrue()
        ->and($freshness->allows($owner))->toBeTrue();
    $this->actingAs($admin)->withSession([
        StandaloneAccess::SESSION_VERSION_KEY => $admin->auth_session_version,
    ])->get('/thin-host/admin-operation')->assertOk()->assertSeeText('managed admin operation');
    expect($admin->fresh()->membership_confirmed_at?->toAtomString())->toBe('2026-09-10T12:00:00+00:00');

    $failure = false;
    CarbonImmutable::setTestNow('2026-09-10T12:10:00+00:00');
    $this->get('/thin-host/admin-operation')->assertOk();
    expect($admin->fresh()->membership_confirmed_at?->toAtomString())->toBe('2026-09-10T12:10:00+00:00');

    CarbonImmutable::setTestNow('2026-09-10T12:14:59+00:00');
    $this->get('/thin-host/admin-operation')->assertOk();
    $callsAfterResetWindow = p3cConfirmationCalls($fixture);
    CarbonImmutable::setTestNow('2026-09-10T12:15:00+00:00');
    $failure = true;
    $this->get('/thin-host/admin-operation')->assertOk();
    expect($admin->fresh()->membership_confirmed_at?->toAtomString())->toBe('2026-09-10T12:10:00+00:00')
        ->and(p3cConfirmationCalls($fixture))->toBe($callsAfterResetWindow + 1);

    CarbonImmutable::setTestNow('2026-09-10T12:39:59+00:00');
    $this->get('/thin-host/admin-operation')->assertOk();
    expect($admin->fresh()->membership_confirmed_at?->toAtomString())->toBe('2026-09-10T12:10:00+00:00');
    CarbonImmutable::setTestNow('2026-09-10T12:40:00+00:00');
    $this->get('/thin-host/admin-operation')->assertForbidden();
    expect($admin->fresh()->membership_confirmed_at?->toAtomString())->toBe('2026-09-10T12:10:00+00:00');
});

it('refuses a confirmation for another subject with zero freshness writes', function (): void {
    CarbonImmutable::setTestNow('2026-09-10T12:00:00+00:00');
    $fixture = p3cConfigureAuthority();
    $user = p3cUser();
    $before = $user->getAttributes();
    $fixture->confirmationOverrides = ['scalpels_id' => 'another-subject'];

    CarbonImmutable::setTestNow('2026-09-10T12:05:00+00:00');
    expect(app(ManagedFreshness::class)->allows($user))->toBeTrue()
        ->and($user->fresh()->getAttributes())->toBe($before);
});

it('keeps membership denial subject-local and connection denial installation-wide while deployment credentials survive both', function (string $membershipStatus): void {
    CarbonImmutable::setTestNow('2026-09-10T12:00:00+00:00');
    p3cConfigureAuthority();
    $a = p3cUser('blast-a', sequence: 10);
    $b = p3cUser('blast-b', sequence: 10);
    $c = p3cUser('blast-c', sequence: 10);
    $foreign = p3cUser('blast-foreign', sequence: 10);
    $foreign->forceFill(['scalpels_connection_id' => 'another-connection'])->save();
    $credentials = [
        'a' => p3cAccountCredential($a, 'blast-a-secret'),
        'b' => p3cAccountCredential($b, 'blast-b-secret'),
        'c' => p3cAccountCredential($c, 'blast-c-secret'),
        'foreign' => p3cAccountCredential($foreign, 'blast-foreign-secret'),
    ];
    $deployment = p3cDeploymentCredential($a, 'blast-deployment-secret');

    foreach (['a' => $a, 'b' => $b, 'c' => $c, 'foreign' => $foreign] as $key => $user) {
        p3cSession($user, 'blast-session-'.$key);
    }

    $resolver = app(CredentialResolver::class);
    expect($resolver->resolve(CredentialKind::Bearer, 'blast-deployment-secret')?->is($deployment))->toBeTrue();

    $responses = app(ManagedMembershipResponses::class);
    expect($responses->applyConfirmation(
        p3cConnection(),
        $a,
        p3cConfirmation($a, 20, membershipStatus: $membershipStatus, role: 'admin'),
    ))->toBeFalse();

    expect($a->fresh()->status)->toBe('inactive')
        ->and($a->fresh()->role)->toBe('member')
        ->and($a->fresh()->managed_membership_status)->toBe($membershipStatus)
        ->and($a->fresh()->auth_session_version)->toBe(2)
        ->and($credentials['a']->refresh()->revoked_at)->not->toBeNull()
        ->and(DB::table('sessions')->where('id', 'blast-session-a')->exists())->toBeFalse()
        ->and($b->fresh()->status)->toBe('active')
        ->and($b->fresh()->auth_session_version)->toBe(1)
        ->and($credentials['b']->refresh()->revoked_at)->toBeNull()
        ->and(DB::table('sessions')->where('id', 'blast-session-b')->exists())->toBeTrue()
        ->and($c->fresh()->auth_session_version)->toBe(1)
        ->and($credentials['c']->refresh()->revoked_at)->toBeNull()
        ->and($foreign->fresh()->auth_session_version)->toBe(1)
        ->and($credentials['foreign']->refresh()->revoked_at)->toBeNull()
        ->and($deployment->refresh()->revoked_at)->toBeNull()
        ->and($resolver->resolve(CredentialKind::Bearer, 'blast-deployment-secret')?->is($deployment))->toBeTrue();

    expect($responses->applyConfirmation(
        p3cConnection(),
        $b,
        p3cConfirmation($b, 21, connectionStatus: 'inactive'),
    ))->toBeFalse();

    expect(DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->value('managed_connection_status'))->toBe('inactive')
        ->and($a->fresh()->auth_session_version)->toBe(3)
        ->and($b->fresh()->auth_session_version)->toBe(2)
        ->and($c->fresh()->auth_session_version)->toBe(2)
        ->and($credentials['b']->refresh()->revoked_at)->not->toBeNull()
        ->and($credentials['c']->refresh()->revoked_at)->not->toBeNull()
        ->and(DB::table('sessions')->whereIn('id', ['blast-session-b', 'blast-session-c'])->exists())->toBeFalse()
        ->and($foreign->fresh()->auth_session_version)->toBe(1)
        ->and($credentials['foreign']->refresh()->revoked_at)->toBeNull()
        ->and(DB::table('sessions')->where('id', 'blast-session-foreign')->exists())->toBeTrue()
        ->and($deployment->refresh()->revoked_at)->toBeNull()
        ->and($resolver->resolve(CredentialKind::Bearer, 'blast-deployment-secret')?->is($deployment))->toBeTrue();

    expect($responses->applyConfirmation(
        p3cConnection(),
        $c,
        p3cConfirmation($c, 22),
    ))->toBeTrue();
    expect(DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->value('managed_connection_status'))->toBe('active')
        ->and($a->fresh()->managed_membership_status)->toBe($membershipStatus)
        ->and($a->fresh()->status)->toBe('inactive')
        ->and($b->fresh()->managed_membership_status)->toBe('active')
        ->and($credentials['b']->refresh()->revoked_at)->not->toBeNull()
        ->and($credentials['c']->refresh()->revoked_at)->not->toBeNull()
        ->and($deployment->refresh()->revoked_at)->toBeNull();
})->with(['removed', 'disabled']);

it('applies non-Owner promotion and demotion on the next authorization decision', function (): void {
    CarbonImmutable::setTestNow('2026-09-10T12:00:00+00:00');
    p3cConfigureAuthority();
    $user = p3cUser('role-subject', sequence: 10);
    $responses = app(ManagedMembershipResponses::class);
    Route::middleware(['web', 'bfc.admin'])->get('/managed-role-decision', static fn (): string => 'authorized');

    $this->actingAsVersioned($user)->get('/managed-role-decision')->assertForbidden();
    expect($responses->applyConfirmation(
        p3cConnection(),
        $user,
        p3cConfirmation($user, 20, role: 'admin'),
    ))->toBeTrue();
    $this->actingAsVersioned($user->fresh())->get('/managed-role-decision')->assertOk()->assertSeeText('authorized');

    expect($responses->applyConfirmation(
        p3cConnection(),
        $user,
        p3cConfirmation($user, 21, role: 'member'),
    ))->toBeTrue();
    $this->actingAsVersioned($user->fresh())->get('/managed-role-decision')->assertForbidden();
});

it('refuses unknown or absent roles without defaulting to member or treating malformed input as revocation', function (string $shape): void {
    CarbonImmutable::setTestNow('2026-09-10T12:00:00+00:00');
    $fixture = p3cConfigureAuthority();
    $user = p3cUser('unknown-role-subject', 'admin', 10);
    $credential = p3cAccountCredential($user, 'unknown-role-secret');
    p3cSession($user, 'unknown-role-session');
    $confirmedAt = $user->membership_confirmed_at?->toAtomString();
    $responseAt = $user->membership_response_at?->toAtomString();

    $fixture->confirmationResponder = static function (array $request, array $payload) use ($shape): mixed {
        if ($shape === 'unknown') {
            return Http::response(array_merge($payload, ['role' => 'super-admin']));
        }

        unset($payload['role']);

        return Http::response($payload);
    };

    CarbonImmutable::setTestNow('2026-09-10T12:05:00+00:00');
    expect(app(ManagedFreshness::class)->allows($user))->toBeTrue();
    $user->refresh();
    expect($user->role)->toBe('admin')
        ->and($user->managed_membership_role)->toBe('admin')
        ->and($user->status)->toBe('active')
        ->and($user->membership_confirmed_at?->toAtomString())->toBe($confirmedAt)
        ->and($user->membership_response_at?->toAtomString())->toBe($responseAt)
        ->and($user->membership_checked_at?->toAtomString())->toBe(now()->toAtomString())
        ->and($credential->refresh()->revoked_at)->toBeNull()
        ->and(DB::table('sessions')->where('id', 'unknown-role-session')->exists())->toBeTrue();
})->with(['unknown', 'absent']);

it('returns false instead of throwing when a managed subject is not bound to the current connection', function (): void {
    p3cConfigureAuthority();
    $user = p3cUser();
    $user->forceFill(['scalpels_connection_id' => 'another-connection'])->save();

    expect(app(ManagedFreshness::class)->allows($user))->toBeFalse();
});

it('treats every authority failure class as infrastructure without revoking account state', function (string $failure): void {
    CarbonImmutable::setTestNow('2026-09-10T12:00:00+00:00');
    $fixture = p3cConfigureAuthority();
    $user = p3cUser('infrastructure-subject', sequence: 10);
    $credential = p3cAccountCredential($user, 'infrastructure-secret');
    p3cSession($user, 'infrastructure-session');
    $confirmedAt = $user->membership_confirmed_at?->toAtomString();
    $responseAt = $user->membership_response_at?->toAtomString();
    $fixture->confirmationResponder = static function () use ($failure): mixed {
        if ($failure === 'transport') {
            throw new RuntimeException('fixture transport failure');
        }

        if ($failure === 'malformed') {
            return Http::response('not-json');
        }

        $status = (int) $failure;

        return Http::response([
            'contract_version' => 'managed-auth-v1',
            'error' => 'fixture_failure',
        ], $status);
    };

    CarbonImmutable::setTestNow('2026-09-10T12:05:00+00:00');
    expect(app(ManagedFreshness::class)->allows($user))->toBeTrue();
    $user->refresh();
    expect($user->status)->toBe('active')
        ->and($user->membership_confirmed_at?->toAtomString())->toBe($confirmedAt)
        ->and($user->membership_response_at?->toAtomString())->toBe($responseAt)
        ->and($user->membership_checked_at?->toAtomString())->toBe(now()->toAtomString())
        ->and($credential->refresh()->revoked_at)->toBeNull()
        ->and(DB::table('sessions')->where('id', 'infrastructure-session')->exists())->toBeTrue();
})->with([
    'success-like unlisted code' => '201',
    'invalid grant' => '400',
    'invalid client' => '401',
    'unlisted client failure' => '418',
    'rate limit' => '429',
    'server error' => '500',
    'unavailable' => '503',
    'transport failure' => 'transport',
    'malformed 200 body' => 'malformed',
]);

it('ends the expired browser session without revoking and resolves the same credential after a later success', function (): void {
    CarbonImmutable::setTestNow('2026-09-10T12:00:00+00:00');
    $fixture = p3cConfigureAuthority();
    p3cConfigureCredentialGuard();
    $user = p3cUser('restored-subject');
    $credential = p3cAccountCredential($user, 'restored-account-secret');
    $userId = $user->getKey();
    $credentialId = $credential->id;
    Route::middleware(['web', 'bfc.auth'])->get('/managed-ingress/browser', static fn (): string => 'allowed');
    Route::middleware('auth:bfc')->get('/managed-ingress/credential', static function (): array {
        $guard = auth('bfc');

        return ['credential' => $guard instanceof CredentialGuard ? $guard->credential()?->id : null];
    });
    $fixture->confirmationResponder = static fn (): mixed => Http::response([
        'contract_version' => 'managed-auth-v1',
        'error' => 'server_error',
    ], 503);

    CarbonImmutable::setTestNow('2026-09-10T12:30:00+00:00');
    $this->actingAsVersioned($user)->getJson('/managed-ingress/browser')->assertUnauthorized();
    $this->assertGuest('web');
    $this->getJson('/managed-ingress/credential', [
        'Authorization' => 'Bearer restored-account-secret',
    ])->assertUnauthorized();

    expect($credential->refresh()->id)->toBe($credentialId)
        ->and($credential->revoked_at)->toBeNull()
        ->and($credential->status->value)->toBe('active')
        ->and(User::query()->whereKey($userId)->count())->toBe(1)
        ->and($user->fresh()->membership_confirmed_at?->toAtomString())->toBe('2026-09-10T12:00:00+00:00');

    $fixture->confirmationResponder = null;
    CarbonImmutable::setTestNow('2026-09-10T12:30:30+00:00');
    $this->getJson('/managed-ingress/credential', [
        'Authorization' => 'Bearer restored-account-secret',
    ])->assertOk()->assertJsonPath('credential', $credentialId);

    expect(User::query()->whereKey($userId)->count())->toBe(1)
        ->and(User::query()->where('scalpels_id', 'restored-subject')->sole()->getKey())->toBe($userId)
        ->and($credential->refresh()->id)->toBe($credentialId)
        ->and($credential->revoked_at)->toBeNull()
        ->and($credential->last_used_at)->not->toBeNull()
        ->and($user->fresh()->membership_confirmed_at?->toAtomString())->toBe(now()->toAtomString());
});

it('enforces deadline and authoritative denial on the bfc guard through BearerAuthenticator and CredentialResolver', function (string $outcome): void {
    CarbonImmutable::setTestNow('2026-09-10T12:00:00+00:00');
    $fixture = p3cConfigureAuthority();
    p3cConfigureCredentialGuard();
    $user = p3cUser('bearer-ingress-'.$outcome);
    $secret = 'bearer-ingress-'.$outcome.'-secret';
    $credential = p3cAccountCredential($user, $secret);
    Route::middleware('auth:bfc')->get('/managed-ingress/bearer-'.$outcome, static fn (): string => 'allowed');
    $this->getJson('/managed-ingress/bearer-'.$outcome, [
        'Authorization' => 'Bearer '.$secret,
    ])->assertOk();
    $lastUsedAt = $credential->fresh()->last_used_at?->toAtomString();

    if ($outcome === 'deadline') {
        $fixture->confirmationResponder = static fn (): mixed => Http::response([
            'contract_version' => 'managed-auth-v1',
            'error' => 'server_error',
        ], 503);
        CarbonImmutable::setTestNow('2026-09-10T12:30:00+00:00');
    } else {
        $fixture->confirmationOverrides = ['membership_status' => 'removed'];
        CarbonImmutable::setTestNow('2026-09-10T12:05:00+00:00');
    }

    $this->getJson('/managed-ingress/bearer-'.$outcome, [
        'Authorization' => 'Bearer '.$secret,
    ])->assertUnauthorized();

    expect($credential->refresh()->last_used_at?->toAtomString())->toBe($lastUsedAt)
        ->and($credential->revoked_at === null)->toBe($outcome === 'deadline');
})->with(['deadline', 'authoritative']);

it('enforces deadline and authoritative denial on the bfc guard through BasicAuthenticator and CredentialResolver', function (string $outcome): void {
    CarbonImmutable::setTestNow('2026-09-10T12:00:00+00:00');
    $fixture = p3cConfigureAuthority();
    p3cConfigureCredentialGuard();
    $user = p3cUser('basic-ingress-'.$outcome);
    $secret = 'basic-ingress-'.$outcome.'-secret';
    $credential = p3cAccountCredential($user, $secret, CredentialKind::Basic);
    Route::middleware('auth:bfc')->get('/managed-ingress/basic-'.$outcome, static fn (): string => 'allowed');
    $this->getJson('/managed-ingress/basic-'.$outcome, [
        'Authorization' => 'Basic '.base64_encode('credential:'.$secret),
    ])->assertOk();
    $lastUsedAt = $credential->fresh()->last_used_at?->toAtomString();

    if ($outcome === 'deadline') {
        $fixture->confirmationResponder = static fn (): mixed => Http::response([
            'contract_version' => 'managed-auth-v1',
            'error' => 'server_error',
        ], 503);
        CarbonImmutable::setTestNow('2026-09-10T12:30:00+00:00');
    } else {
        $fixture->confirmationOverrides = ['membership_status' => 'removed'];
        CarbonImmutable::setTestNow('2026-09-10T12:05:00+00:00');
    }

    $this->getJson('/managed-ingress/basic-'.$outcome, [
        'Authorization' => 'Basic '.base64_encode('credential:'.$secret),
    ])->assertUnauthorized();

    expect($credential->refresh()->last_used_at?->toAtomString())->toBe($lastUsedAt)
        ->and($credential->revoked_at === null)->toBe($outcome === 'deadline');
})->with(['deadline', 'authoritative']);

it('enforces deadline and authoritative denial on bfc.auth browser routes', function (string $outcome): void {
    CarbonImmutable::setTestNow('2026-09-10T12:00:00+00:00');
    $fixture = p3cConfigureAuthority();
    $user = p3cUser('browser-auth-'.$outcome);
    Route::middleware(['web', 'bfc.auth'])->get('/managed-ingress/user-auth-'.$outcome, static fn (): string => 'allowed');
    $this->actingAsVersioned($user)->getJson('/managed-ingress/user-auth-'.$outcome)->assertOk();

    if ($outcome === 'deadline') {
        $fixture->confirmationResponder = static fn (): mixed => Http::response([
            'contract_version' => 'managed-auth-v1',
            'error' => 'server_error',
        ], 503);
        CarbonImmutable::setTestNow('2026-09-10T12:30:00+00:00');
    } else {
        $fixture->confirmationOverrides = ['membership_status' => 'removed'];
        CarbonImmutable::setTestNow('2026-09-10T12:05:00+00:00');
    }

    $this->actingAsVersioned($user)->getJson('/managed-ingress/user-auth-'.$outcome)->assertUnauthorized();
    $this->assertGuest('web');
})->with(['deadline', 'authoritative']);

it('enforces deadline and authoritative denial on bfc.admin browser routes', function (string $outcome): void {
    CarbonImmutable::setTestNow('2026-09-10T12:00:00+00:00');
    $fixture = p3cConfigureAuthority();
    $user = p3cUser('browser-admin-'.$outcome, 'admin');
    Route::middleware(['web', 'bfc.admin'])->get('/managed-ingress/user-admin-'.$outcome, static fn (): string => 'allowed');
    $this->actingAsVersioned($user)->getJson('/managed-ingress/user-admin-'.$outcome)->assertOk();

    if ($outcome === 'deadline') {
        $fixture->confirmationResponder = static fn (): mixed => Http::response([
            'contract_version' => 'managed-auth-v1',
            'error' => 'server_error',
        ], 503);
        CarbonImmutable::setTestNow('2026-09-10T12:30:00+00:00');
    } else {
        $fixture->confirmationOverrides = ['membership_status' => 'removed', 'role' => 'admin'];
        CarbonImmutable::setTestNow('2026-09-10T12:05:00+00:00');
    }

    $this->actingAsVersioned($user)->getJson('/managed-ingress/user-admin-'.$outcome)->assertForbidden();
    $this->assertGuest('web');
})->with(['deadline', 'authoritative']);

it('enforces deadline and authoritative denial through EnsureCredentialAbility', function (string $outcome): void {
    CarbonImmutable::setTestNow('2026-09-10T12:00:00+00:00');
    $fixture = p3cConfigureAuthority();
    p3cConfigureCredentialGuard();
    $user = p3cUser('ability-'.$outcome);
    $secret = 'ability-'.$outcome.'-secret';
    $credential = p3cAccountCredential($user, $secret, abilities: [OperatorAbility::CredentialRead->value]);
    Route::middleware(['auth:bfc', 'bfc.ability:'.OperatorAbility::CredentialRead->value])
        ->get('/managed-ingress/ability-'.$outcome, static fn (): string => 'allowed');
    $this->getJson('/managed-ingress/ability-'.$outcome, [
        'Authorization' => 'Bearer '.$secret,
    ])->assertOk();
    $lastUsedAt = $credential->fresh()->last_used_at?->toAtomString();

    if ($outcome === 'deadline') {
        $fixture->confirmationResponder = static fn (): mixed => Http::response([
            'contract_version' => 'managed-auth-v1',
            'error' => 'server_error',
        ], 503);
        CarbonImmutable::setTestNow('2026-09-10T12:30:00+00:00');
    } else {
        $fixture->confirmationOverrides = ['membership_status' => 'removed'];
        CarbonImmutable::setTestNow('2026-09-10T12:05:00+00:00');
    }

    $this->getJson('/managed-ingress/ability-'.$outcome, [
        'Authorization' => 'Bearer '.$secret,
    ])->assertUnauthorized();
    expect($credential->refresh()->last_used_at?->toAtomString())->toBe($lastUsedAt);
})->with(['deadline', 'authoritative']);

it('enforces deadline and authoritative denial through EnsureCredentialAdmin', function (string $outcome): void {
    CarbonImmutable::setTestNow('2026-09-10T12:00:00+00:00');
    $fixture = p3cConfigureAuthority();
    p3cConfigureCredentialGuard();
    $user = p3cUser('credential-admin-'.$outcome);
    $secret = 'credential-admin-'.$outcome.'-secret';
    $credential = p3cAccountCredential(
        $user,
        $secret,
        subjectType: SubjectType::Operator,
        abilities: [OperatorAbility::Admin->value],
    );
    Route::middleware('bfc.credential.admin:'.OperatorAbility::CredentialRead->value)
        ->get('/managed-ingress/credential-admin-'.$outcome, static fn (): string => 'allowed');
    $this->getJson('/managed-ingress/credential-admin-'.$outcome, [
        'Authorization' => 'Bearer '.$secret,
    ])->assertOk();
    $lastUsedAt = $credential->fresh()->last_used_at?->toAtomString();

    if ($outcome === 'deadline') {
        $fixture->confirmationResponder = static fn (): mixed => Http::response([
            'contract_version' => 'managed-auth-v1',
            'error' => 'server_error',
        ], 503);
        CarbonImmutable::setTestNow('2026-09-10T12:30:00+00:00');
    } else {
        $fixture->confirmationOverrides = ['membership_status' => 'removed'];
        CarbonImmutable::setTestNow('2026-09-10T12:05:00+00:00');
    }

    $this->getJson('/managed-ingress/credential-admin-'.$outcome, [
        'Authorization' => 'Bearer '.$secret,
    ])->assertUnauthorized();
    expect($credential->refresh()->last_used_at?->toAtomString())->toBe($lastUsedAt);
})->with(['deadline', 'authoritative']);

it('enforces deadline and authoritative denial through EnsureDashboardCredential', function (string $outcome): void {
    CarbonImmutable::setTestNow('2026-09-10T12:00:00+00:00');
    $fixture = p3cConfigureAuthority();
    p3cConfigureCredentialGuard();
    $user = p3cUser('dashboard-'.$outcome);
    $secret = 'dashboard-'.$outcome.'-secret';
    $credential = p3cAccountCredential(
        $user,
        $secret,
        subjectType: SubjectType::Operator,
        abilities: [OperatorAbility::MetadataRead->value],
    );
    Route::middleware(EnsureDashboardCredential::class)
        ->get('/managed-ingress/dashboard-'.$outcome, static fn (): string => 'allowed');
    $this->getJson('/managed-ingress/dashboard-'.$outcome, [
        'Authorization' => 'Bearer '.$secret,
    ])->assertOk();
    $lastUsedAt = $credential->fresh()->last_used_at?->toAtomString();

    if ($outcome === 'deadline') {
        $fixture->confirmationResponder = static fn (): mixed => Http::response([
            'contract_version' => 'managed-auth-v1',
            'error' => 'server_error',
        ], 503);
        CarbonImmutable::setTestNow('2026-09-10T12:30:00+00:00');
    } else {
        $fixture->confirmationOverrides = ['membership_status' => 'removed'];
        CarbonImmutable::setTestNow('2026-09-10T12:05:00+00:00');
    }

    $this->getJson('/managed-ingress/dashboard-'.$outcome, [
        'Authorization' => 'Bearer '.$secret,
    ])->assertUnauthorized();
    expect($credential->refresh()->last_used_at?->toAtomString())->toBe($lastUsedAt);
})->with(['deadline', 'authoritative']);
