<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\ManagedAuthConfirmation;
use ArtisanBuild\BuiltForCloud\ManagedAuthConnection;
use ArtisanBuild\BuiltForCloud\ManagedAuthExchange;
use ArtisanBuild\BuiltForCloud\ManagedFreshness;
use ArtisanBuild\BuiltForCloud\ManagedHandoff;
use ArtisanBuild\BuiltForCloud\ManagedMembershipResponses;
use ArtisanBuild\BuiltForCloud\StandaloneAccess;
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
        ->and($user->fresh()->managed_membership_role)->toBe('member')
        ->and($user->fresh()->managed_membership_roster_version)->toBe(21)
        ->and($user->fresh()->managed_membership_response_sequence)->toBe(21)
        ->and($user->fresh()->membership_confirmed_at?->toAtomString())->toBe($confirmedAt);
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

it('routes a non-active callback response to refusal without the active upsert', function (): void {
    CarbonImmutable::setTestNow('2026-09-10T12:00:00+00:00');
    p3cConfigureAuthority();
    $user = p3cUser(sequence: 10);
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
        ->and($user->status)->toBe('active')
        ->and($user->role)->toBe('member')
        ->and($user->name)->toBe('subject-fixture')
        ->and($user->original_contact_email)->toBeNull()
        ->and($user->managed_membership_status)->toBe('removed')
        ->and($user->membership_confirmed_at?->toAtomString())->toBe($beforeConfirmed)
        ->and($user->membership_checked_at?->toAtomString())->toBe(now()->toAtomString())
        ->and($user->membership_response_at?->toAtomString())->toBe(now()->toAtomString());
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
