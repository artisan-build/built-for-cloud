<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\RetireConsoleKey;
use ArtisanBuild\BuiltForCloud\Console\AssertionBurn;
use ArtisanBuild\BuiltForCloud\Console\DelegatedActor;
use ArtisanBuild\BuiltForCloud\Tests\Support\PostgresLane;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;

uses(PostgresLane::class)->group('pgsql');

const BFC_POSTGRES_LOCK_TIMEOUT = '750ms';

beforeEach(function (): void {
    config([
        'built-for-cloud.console.issuer' => 'https://scalpels.test',
        'built-for-cloud.console.audience' => 'https://sink.test',
    ]);
});

/**
 * The lock_timeout SQLSTATE is the deterministic observation that another
 * transaction held the row or unique-index entry. No wall-clock assertion is
 * involved.
 */
function expectPostgresLockRefusal(?Throwable $failure, string $message): void
{
    expect($failure)->toBeInstanceOf(QueryException::class, $message)
        ->and((string) $failure?->getCode())->toBe('55P03');
}

it('holds the delegated actor lock from its redemption re-read through login', function (): void {
    $secret = consoleKeypair();
    consoleFileKey('pg-redemption-k1', $secret);

    $actor = DelegatedActor::recordHandoff(consoleAssertionFor(subject: 'postgres-redemption-actor'));
    $probe = $this->postgresLaneProbe();
    $interleaved = false;

    DelegatedActor::saved(function (DelegatedActor $saved) use ($actor, $probe, &$interleaved): void {
        if ($interleaved || $saved->getKey() !== $actor->getKey()) {
            return;
        }

        $interleaved = true;
        $probe->beginTransaction();
        $probe->select('select id from bfc_delegated_actors where id = ? for update', [$actor->getKey()]);
    });

    $token = consoleMint($secret, consoleClaims([
        'sub' => 'postgres-redemption-actor',
    ]), 'pg-redemption-k1');

    $this->postgresLaneConnection()->statement("set lock_timeout = '".BFC_POSTGRES_LOCK_TIMEOUT."'");
    $failure = null;

    try {
        consoleGuard()->redeem($token);
    } catch (Throwable $exception) {
        $failure = $exception;
    } finally {
        if ($probe->transactionLevel() > 0) {
            $probe->rollBack();
        }

        $this->postgresLaneConnection()->statement('set lock_timeout = default');
    }

    expect($interleaved)->toBeTrue();
    expectPostgresLockRefusal(
        $failure,
        'Redemption completed while deactivation held the actor row; the locked re-read is absent.',
    );
})->note('Mutation: remove lockForUpdate() from DelegatedActor::lockedById(). This test must then complete redemption instead of receiving SQLSTATE 55P03. Debt row bfc-console-redemption-lock.');

it('serializes two inserts for one assertion at the unique burn index', function (): void {
    $assertion = consoleAssertionFor(subject: 'postgres-burn-actor');
    $main = $this->postgresLaneConnection();
    $probe = $this->postgresLaneProbe();

    $main->beginTransaction();
    AssertionBurn::burn($assertion, now());

    $probe->statement("set lock_timeout = '".BFC_POSTGRES_LOCK_TIMEOUT."'");
    $probe->beginTransaction();
    $failure = null;

    try {
        $probe->table('bfc_console_assertion_burns')->insert([
            'mint_hash' => AssertionBurn::mintHash($assertion->issuer, $assertion->id),
            'issuer' => $assertion->issuer,
            'mint_id' => $assertion->id,
            'expires_at' => $assertion->expiresAt,
            'redeemed_at' => now(),
        ]);
    } catch (Throwable $exception) {
        $failure = $exception;
    } finally {
        if ($probe->transactionLevel() > 0) {
            $probe->rollBack();
        }

        $main->commit();
        $probe->statement('set lock_timeout = default');
    }

    expectPostgresLockRefusal(
        $failure,
        'A concurrent presentation inserted the same mint before the first redemption committed.',
    );

    expect(AssertionBurn::query()->count())->toBe(1);
})->note('Mutation: remove unique() from the burn ledger mint_hash migration, widening the concurrent insert window. The probe then inserts a duplicate instead of receiving SQLSTATE 55P03. Debt row bfc-console-enter-burn-race.');

it('locks the whole key ring before deciding whether retirement needs confirmation', function (): void {
    consoleFileKey('pg-retire-k1', consoleKeypair());

    $main = $this->postgresLaneConnection();
    $probe = $this->postgresLaneProbe();

    $probe->beginTransaction();
    $probe->select('select id from bfc_console_keys for update');
    $main->statement("set lock_timeout = '".BFC_POSTGRES_LOCK_TIMEOUT."'");
    $failure = null;

    try {
        DB::transaction(fn () => app(RetireConsoleKey::class)('pg-retire-k1', null));
    } catch (Throwable $exception) {
        $failure = $exception;
    } finally {
        if ($probe->transactionLevel() > 0) {
            $probe->rollBack();
        }

        $main->statement('set lock_timeout = default');
    }

    expectPostgresLockRefusal(
        $failure,
        'Retirement read the ring while another retirement held it; the ring lock is absent.',
    );
})->note('Mutation: remove lockForUpdate() from RetireConsoleKey. This test must then reach the last-active-key refusal instead of receiving SQLSTATE 55P03. Debt row console-key-retire-ring-lock.');
