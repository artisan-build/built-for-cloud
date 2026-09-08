<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\AcceptHumanInvitation;
use ArtisanBuild\BuiltForCloud\Invitation;
use ArtisanBuild\BuiltForCloud\Tests\Support\PostgresLane;
use ArtisanBuild\BuiltForCloud\User;
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
