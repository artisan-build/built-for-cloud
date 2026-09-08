<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\AcceptHumanInvitation;
use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\Invitation;
use ArtisanBuild\BuiltForCloud\Tests\Support\PostgresLane;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;

uses(PostgresLane::class)->group('pgsql');

function expectStandalonePostgresLock(?Throwable $failure): void
{
    expect($failure)->toBeInstanceOf(QueryException::class)
        ->and((string) $failure?->getCode())->toBe('55P03');
}

function seedStandalonePostgresAuthority(): void
{
    DB::table('bfc_authority')->insert([
        'key' => InstallationAuthority::KEY,
        'mode' => AuthorityMode::Standalone->value,
        'generation' => 1,
        'created_at' => now(),
        'updated_at' => now(),
    ]);
}

it('burns invitations once and enforces pending invitation and user email uniqueness on Postgres', function (): void {
    expect(Schema::hasTable('password_reset_tokens'))->toBeTrue()
        ->and(Schema::hasTable('sessions'))->toBeTrue();

    $token = bin2hex(random_bytes(32));
    Invitation::query()->create([
        'id' => (string) Str::uuid(),
        'email' => 'postgres-invite@example.test',
        'token' => hash('sha256', $token),
        'invited_by' => '1',
        'role' => 'member',
        'expires_at' => now()->addHour(),
    ]);

    expect(fn () => Invitation::query()->create([
        'id' => (string) Str::uuid(),
        'email' => 'postgres-invite@example.test',
        'token' => hash('sha256', 'other-postgres-token'),
        'invited_by' => '1',
        'role' => 'member',
        'expires_at' => now()->addHour(),
    ]))->toThrow(QueryException::class);

    $accepted = app(AcceptHumanInvitation::class)($token, 'Postgres Invitee', 'postgres invitation password');
    expect($accepted->email)->toBe('postgres-invite@example.test')
        ->and(Hash::check('postgres invitation password', (string) $accepted->password))->toBeTrue();

    expect(fn () => app(AcceptHumanInvitation::class)($token, 'Replay', 'postgres invitation password'))
        ->toThrow(RuntimeException::class);
    expect(fn () => User::query()->create([
        'name' => 'Duplicate Email',
        'email' => 'postgres-invite@example.test',
    ]))->toThrow(QueryException::class);
});

it('holds invitation and membership rows against concurrent burns and role changes on Postgres', function (): void {
    $main = $this->postgresLaneConnection();
    $probe = $this->postgresLaneProbe();
    $user = User::query()->create([
        'name' => 'Postgres Race Member',
        'email' => 'postgres-race-member@example.test',
    ]);
    $invitation = Invitation::query()->create([
        'id' => (string) Str::uuid(),
        'email' => 'postgres-race-invite@example.test',
        'token' => hash('sha256', 'postgres-race-token'),
        'invited_by' => (string) $user->getKey(),
        'role' => 'member',
        'expires_at' => now()->addHour(),
    ]);

    foreach ([
        ['users', $user->getKey(), ['role' => 'admin']],
        ['invitations', $invitation->getKey(), ['accepted_at' => now()]],
    ] as [$table, $id, $update]) {
        $main->beginTransaction();
        $main->table($table)->where('id', $id)->lockForUpdate()->first();
        $probe->statement("set lock_timeout = '750ms'");
        $probe->beginTransaction();
        $failure = null;

        try {
            $probe->table($table)->where('id', $id)->update($update);
        } catch (Throwable $exception) {
            $failure = $exception;
        } finally {
            if ($probe->transactionLevel() > 0) {
                $probe->rollBack();
            }
            $main->rollBack();
            $probe->statement('set lock_timeout = default');
        }

        expectStandalonePostgresLock($failure);
    }

    DB::table('sessions')->insert([
        ['id' => 'postgres-owned', 'user_id' => $user->getKey(), 'payload' => 'test', 'last_activity' => now()->timestamp],
        ['id' => 'postgres-foreign', 'user_id' => $user->getKey() + 1, 'payload' => 'test', 'last_activity' => now()->timestamp],
    ]);

    expect(DB::table('sessions')->where('user_id', $user->getKey())->pluck('id')->all())
        ->toBe(['postgres-owned']);
});

it('holds production membership and invitation operations against independent Postgres writers', function (): void {
    seedStandalonePostgresAuthority();
    $main = $this->postgresLaneConnection();
    $probe = $this->postgresLaneProbe();
    $probe->statement("set lock_timeout = '750ms'");
    $owner = User::query()->create([
        'name' => 'Postgres Controller Owner',
        'email' => 'postgres-controller-owner@example.test',
        'password' => Hash::make('postgres controller password'),
    ]);
    $owner->forceFill(['role' => UserRole::Owner->value, 'email_verified_at' => now()])->save();
    $member = User::query()->create([
        'name' => 'Postgres Controller Member',
        'email' => 'postgres-controller-member@example.test',
        'password' => Hash::make('postgres controller password'),
    ]);
    $membershipLockObserved = false;
    $membershipFailure = null;

    $main->listen(function (QueryExecuted $query) use ($probe, $member, &$membershipLockObserved, &$membershipFailure): void {
        if ($membershipLockObserved
            || ! str_contains(strtolower($query->sql), 'from "users"')
            || ! str_contains(strtolower($query->sql), 'for update')
            || ! in_array($member->getKey(), $query->bindings, false)) {
            return;
        }

        $membershipLockObserved = true;
        $probe->beginTransaction();

        try {
            $probe->table('users')->where('id', $member->getKey())->update(['role' => UserRole::Admin->value]);
        } catch (Throwable $exception) {
            $membershipFailure = $exception;
        } finally {
            $probe->rollBack();
        }
    });

    $this->actingAsVersioned($owner)
        ->put('/bfc/members/'.$member->getKey().'/role', ['role' => UserRole::Admin->value])
        ->assertRedirect();

    expect($membershipLockObserved)->toBeTrue();
    expectStandalonePostgresLock($membershipFailure);
    expect($member->refresh()->role)->toBe(UserRole::Admin->value);

    $deactivationTarget = User::query()->create([
        'name' => 'Postgres Deactivation Target',
        'email' => 'postgres-deactivation-target@example.test',
        'password' => Hash::make('postgres controller password'),
    ]);
    $deactivationLockObserved = false;
    $deactivationFailure = null;

    $main->listen(function (QueryExecuted $query) use ($probe, $deactivationTarget, &$deactivationLockObserved, &$deactivationFailure): void {
        if ($deactivationLockObserved
            || ! str_contains(strtolower($query->sql), 'from "users"')
            || ! str_contains(strtolower($query->sql), 'for update')
            || ! in_array($deactivationTarget->getKey(), $query->bindings, false)) {
            return;
        }

        $deactivationLockObserved = true;
        $probe->beginTransaction();

        try {
            $probe->table('users')->where('id', $deactivationTarget->getKey())->update(['status' => 'inactive']);
        } catch (Throwable $exception) {
            $deactivationFailure = $exception;
        } finally {
            $probe->rollBack();
        }
    });

    $this->delete('/bfc/members/'.$deactivationTarget->getKey())->assertRedirect();

    expect($deactivationLockObserved)->toBeTrue();
    expectStandalonePostgresLock($deactivationFailure);
    expect($deactivationTarget->refresh()->status)->toBe('inactive');

    $token = bin2hex(random_bytes(32));
    $tokenHash = hash('sha256', $token);
    Invitation::query()->create([
        'id' => (string) Str::uuid(),
        'email' => 'postgres-controller-invite@example.test',
        'token' => $tokenHash,
        'invited_by' => (string) $owner->getKey(),
        'role' => UserRole::Member->value,
        'expires_at' => now()->addHour(),
    ]);
    $invitationLockObserved = false;
    $invitationFailure = null;

    $main->listen(function (QueryExecuted $query) use ($probe, $tokenHash, &$invitationLockObserved, &$invitationFailure): void {
        if ($invitationLockObserved
            || ! str_contains(strtolower($query->sql), 'from "invitations"')
            || ! str_contains(strtolower($query->sql), 'for update')
            || ! in_array($tokenHash, $query->bindings, true)) {
            return;
        }

        $invitationLockObserved = true;
        $probe->beginTransaction();

        try {
            $probe->table('invitations')->where('token', $tokenHash)->update(['accepted_at' => now()]);
        } catch (Throwable $exception) {
            $invitationFailure = $exception;
        } finally {
            $probe->rollBack();
        }
    });

    $accepted = app(AcceptHumanInvitation::class)($token, 'Postgres Controller Invitee', 'postgres invitation password');

    expect($invitationLockObserved)->toBeTrue();
    expectStandalonePostgresLock($invitationFailure);
    expect($accepted->email)->toBe('postgres-controller-invite@example.test');
    $probe->statement('set lock_timeout = default');
});

it('runs password reset burn and owned session controllers on Postgres', function (): void {
    seedStandalonePostgresAuthority();
    config([
        'session.driver' => 'database',
        'session.connection' => 'pgsql_testing',
        'session.table' => 'sessions',
    ]);
    $user = User::query()->create([
        'name' => 'Postgres Lifecycle User',
        'email' => 'postgres-lifecycle@example.test',
        'password' => Hash::make('postgres original password'),
    ]);
    $user->forceFill(['email_verified_at' => now()])->save();
    $token = bin2hex(random_bytes(32));
    DB::table('password_reset_tokens')->insert([
        'email' => $user->email,
        'token' => hash('sha256', $token),
        'created_at' => now(),
    ]);
    DB::table('sessions')->insert([
        'id' => 'postgres-reset-session',
        'user_id' => $user->getKey(),
        'payload' => 'test',
        'last_activity' => now()->timestamp,
    ]);

    $this->post('/bfc/reset-password', [
        'token' => $token,
        'email' => $user->email,
        'password' => 'postgres replacement password',
        'password_confirmation' => 'postgres replacement password',
    ])->assertRedirect(route('bfc.login'));

    expect(Hash::check('postgres replacement password', (string) $user->refresh()->password))->toBeTrue()
        ->and(DB::table('password_reset_tokens')->where('email', $user->email)->exists())->toBeFalse()
        ->and(DB::table('sessions')->where('id', 'postgres-reset-session')->exists())->toBeFalse();

    DB::table('sessions')->insert([
        [
            'id' => 'postgres-owned-controller-session',
            'user_id' => $user->getKey(),
            'payload' => 'test',
            'last_activity' => now()->timestamp,
            'ip_address' => '192.0.2.10',
            'user_agent' => 'postgres-owned-agent',
        ],
        [
            'id' => 'postgres-foreign-controller-session',
            'user_id' => $user->getKey() + 1,
            'payload' => 'test',
            'last_activity' => now()->timestamp,
            'ip_address' => '192.0.2.20',
            'user_agent' => 'postgres-foreign-agent',
        ],
    ]);

    $this->actingAsVersioned($user)
        ->get('/bfc/me/sessions')
        ->assertOk()
        ->assertSee('postgres-owned-agent')
        ->assertDontSee('postgres-foreign-agent');
    $this->delete('/bfc/me/sessions/postgres-foreign-controller-session', [
        'password' => 'postgres replacement password',
    ])->assertNotFound();
    expect(DB::table('sessions')->where('id', 'postgres-foreign-controller-session')->exists())->toBeTrue();
    $this->delete('/bfc/me/sessions/postgres-owned-controller-session', [
        'password' => 'postgres replacement password',
    ])->assertRedirect();
    expect(DB::table('sessions')->where('id', 'postgres-owned-controller-session')->exists())->toBeFalse();
});
