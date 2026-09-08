<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\Tests\Support\PostgresLane;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Database\QueryException;
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

    expect(InstallationAuthority::query()->count())->toBe(1);

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
});

it('serializes concurrent authority generation changes on Postgres', function (): void {
    $main = $this->postgresLaneConnection();
    $probe = $this->postgresLaneProbe();
    InstallationAuthority::query()->create([
        'key' => InstallationAuthority::KEY,
        'mode' => AuthorityMode::Standalone->value,
        'generation' => 1,
    ]);
    $initial = InstallationAuthority::current('pgsql_testing');

    $main->beginTransaction();
    $changed = InstallationAuthority::change($initial, AuthorityMode::Managed, 'pgsql_testing');
    $probe->statement("set lock_timeout = '750ms'");
    $failure = null;

    try {
        InstallationAuthority::change($initial, AuthorityMode::Managed, 'pgsql_testing_probe');
    } catch (Throwable $exception) {
        $failure = $exception;
    } finally {
        if ($probe->transactionLevel() > 0) {
            $probe->rollBack();
        }

        $main->commit();
        $probe->statement('set lock_timeout = default');
    }

    expect($changed?->generation)->toBe(2)
        ->and($failure)->toBeInstanceOf(QueryException::class)
        ->and((string) $failure?->getCode())->toBe('55P03')
        ->and(InstallationAuthority::current('pgsql_testing')->generation)->toBe(2)
        ->and(InstallationAuthority::query()->count())->toBe(1);
});
