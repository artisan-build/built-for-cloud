<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\AuthorityState;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\Tests\Support\PostgresLane;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

uses(PostgresLane::class)->group('pgsql');

it('migrates and enforces canonical human uniqueness on Postgres', function (): void {
    expect(Schema::hasColumns('users', [
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
        'membership_confirmed_at',
        'membership_checked_at',
        'membership_response_at',
    ]))->toBeTrue();

    User::query()->create(['name' => 'Postgres One', 'email' => 'postgres@example.test'])
        ->forceFill([
            'scalpels_issuer' => 'https://scalpels.example',
            'scalpels_connection_id' => 'connection-pg',
            'scalpels_id' => 'subject-pg',
        ])->save();

    expect(fn () => User::query()->create(['name' => 'Duplicate', 'email' => 'postgres@example.test']))
        ->toThrow(QueryException::class);

    expect(function (): void {
        User::query()->create(['name' => 'External Duplicate', 'email' => 'external-pg@example.test'])
            ->forceFill([
                'scalpels_issuer' => 'https://scalpels.example',
                'scalpels_connection_id' => 'connection-pg',
                'scalpels_id' => 'subject-pg',
            ])->save();
    })->toThrow(QueryException::class);

    foreach ([
        ['https://scalpels.example', null, null],
        [null, 'connection-partial', null],
        [null, null, 'subject-partial'],
        ['https://scalpels.example', 'connection-partial', null],
        ['https://scalpels.example', null, 'subject-partial'],
        [null, 'connection-partial', 'subject-partial'],
    ] as $index => [$issuer, $connection, $subject]) {
        expect(fn (): bool => DB::table('users')->insert([
            'name' => 'Partial '.$index,
            'email' => 'partial-pg-'.$index.'@example.test',
            'role' => 'member',
            'status' => 'active',
            'scalpels_issuer' => $issuer,
            'scalpels_connection_id' => $connection,
            'scalpels_id' => $subject,
            'email_is_generated' => false,
        ]))->toThrow(QueryException::class);
    }

    $first = User::query()->create(['name' => 'Owner One', 'email' => 'owner-one-pg@example.test']);
    $second = User::query()->create(['name' => 'Owner Two', 'email' => 'owner-two-pg@example.test']);

    expect(fn (): int => User::query()->whereKey([$first->getKey(), $second->getKey()])->update([
        'role' => 'owner',
    ]))->toThrow(QueryException::class);

    DB::table('users')->where('id', $first->getKey())->update(['role' => 'owner']);

    expect(fn (): int => DB::table('users')->where('id', $second->getKey())->update(['role' => 'owner']))
        ->toThrow(QueryException::class);

    User::query()->whereKey($second->getKey())->update(['role' => 'admin']);
    User::query()->create(['name' => 'Admin Two', 'email' => 'admin-two-pg@example.test'])
        ->forceFill(['role' => 'admin'])->save();
    User::query()->create(['name' => 'Member', 'email' => 'member-pg@example.test']);

    expect(User::query()->where('role', 'owner')->count())->toBe(1)
        ->and(User::query()->where('role', 'admin')->count())->toBe(2);
});

it('rejects invalid authority rows and non-monotonic writes on Postgres', function (): void {
    DB::table('bfc_authority')->insert([
        'key' => InstallationAuthority::KEY,
        'mode' => AuthorityMode::Standalone->value,
        'generation' => 1,
    ]);

    expect(fn (): bool => DB::table('bfc_authority')->insert([
        'key' => 'another-installation',
        'mode' => AuthorityMode::Standalone->value,
        'generation' => 1,
    ]))->toThrow(QueryException::class);

    expect(fn (): int => DB::table('bfc_authority')->update([
        'mode' => AuthorityMode::Managed->value,
    ]))->toThrow(QueryException::class);

    expect(fn (): int => DB::table('bfc_authority')->update(['generation' => 0]))
        ->toThrow(QueryException::class);

    $changed = InstallationAuthority::change(
        InstallationAuthority::current('pgsql_testing'),
        AuthorityMode::Managed,
        'pgsql_testing',
    );

    expect($changed?->generation)->toBe(2);

    expect(fn (): int => DB::table('bfc_authority')->update(['generation' => 1]))
        ->toThrow(QueryException::class);

    expect(fn (): int => DB::table('bfc_authority')->update([
        'mode' => 'unexpected',
        'generation' => 3,
    ]))->toThrow(QueryException::class);

    expect(fn (): int => DB::table('bfc_authority')->delete())
        ->toThrow(QueryException::class);

    expect(InstallationAuthority::change(
        AuthorityState::fromRaw('unexpected', 2),
        AuthorityMode::Standalone,
        'pgsql_testing',
    ))->toBeNull()
        ->and(InstallationAuthority::current('pgsql_testing')->generation)->toBe(2)
        ->and(DB::table('bfc_authority')->count())->toBe(1);
});

it('returns null after a blocked stale authority writer resumes on Postgres', function (): void {
    $main = $this->postgresLaneConnection();
    DB::table('bfc_authority')->insert([
        'key' => InstallationAuthority::KEY,
        'mode' => AuthorityMode::Standalone->value,
        'generation' => 1,
    ]);
    $initial = InstallationAuthority::current('pgsql_testing');
    $applicationName = 'bfc-authority-cas-loser-'.bin2hex(random_bytes(6));
    $main->beginTransaction();
    $winner = InstallationAuthority::change($initial, AuthorityMode::Managed, 'pgsql_testing');
    $process = proc_open(
        [PHP_BINARY, __DIR__.'/Fixtures/authority-cas-loser.php', $applicationName],
        [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ],
        $pipes,
        dirname(__DIR__),
    );

    if (! is_resource($process)) {
        $main->rollBack();
        throw new RuntimeException('Could not start the authority CAS loser process.');
    }

    fclose($pipes[0]);
    $ready = trim((string) fgets($pipes[1]));
    $blocked = false;
    $deadline = microtime(true) + 5;

    while (! $blocked && microtime(true) < $deadline) {
        $activity = $main->selectOne(
            'select exists (
                select 1 from pg_stat_activity
                where application_name = ? and cardinality(pg_blocking_pids(pid)) > 0
            ) as blocked',
            [$applicationName],
        );
        $blocked = is_object($activity) && (bool) $activity->blocked;
    }

    $main->commit();
    $result = json_decode(stream_get_contents($pipes[1]), true, flags: JSON_THROW_ON_ERROR);
    $error = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $status = proc_close($process);

    expect($ready)->toBe('ready')
        ->and($blocked)->toBeTrue()
        ->and($status)->toBe(0)
        ->and($error)->toBe('')
        ->and($winner?->mode)->toBe(AuthorityMode::Managed)
        ->and($winner?->generation)->toBe(2)
        ->and($result)->toBe(['mode' => null, 'generation' => null])
        ->and(InstallationAuthority::current('pgsql_testing')->generation)->toBe(2);
});
