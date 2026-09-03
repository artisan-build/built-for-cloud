<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\RetireConsoleKey;
use ArtisanBuild\BuiltForCloud\Console\AssertionBurn;
use ArtisanBuild\BuiltForCloud\Console\DelegatedActor;
use ArtisanBuild\BuiltForCloud\Http\Middleware\AuthenticateMcp;
use ArtisanBuild\BuiltForCloud\Tests\Support\PostgresLane;
use Illuminate\Database\QueryException;
use Illuminate\Http\Request;
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

it('serializes concurrent presentation through AuthenticateMcp own transaction', function (): void {
    $secret = consoleKeypair();
    consoleFileKey('pg-mcp-k1', $secret);

    $token = consoleMint($secret, consoleClaims(['purpose' => 'mcp']), 'pg-mcp-k1');
    $probe = $this->postgresLaneProbe();
    $probe->statement("set lock_timeout = '".BFC_POSTGRES_LOCK_TIMEOUT."'");

    $interleaved = false;
    $probeFailure = null;

    AssertionBurn::created(function () use ($token, $probe, &$interleaved, &$probeFailure): void {
        if ($interleaved) {
            return;
        }

        $interleaved = true;
        config(['database.default' => 'pgsql_testing_probe']);

        try {
            app(AuthenticateMcp::class)->handle(
                Request::create('/mcp', 'POST', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$token]),
                fn () => response()->json(['ok' => true]),
            );
        } catch (Throwable $failure) {
            $probeFailure = $failure;
        } finally {
            config(['database.default' => 'pgsql_testing']);

            if ($probe->transactionLevel() > 0) {
                $probe->rollBack();
            }
        }
    });

    try {
        $response = app(AuthenticateMcp::class)->handle(
            Request::create('/mcp', 'POST', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$token]),
            fn () => response()->json(['ok' => true]),
        );
    } finally {
        $probe->statement('set lock_timeout = default');
    }

    expect($response->getStatusCode())->toBe(200)
        ->and($interleaved)->toBeTrue()
        ->and(AssertionBurn::query()->count())->toBe(1);

    expectPostgresLockRefusal(
        $probeFailure,
        'A concurrent MCP presentation passed the middleware transaction before the first burn committed.',
    );

    $replay = app(AuthenticateMcp::class)->handle(
        Request::create('/mcp', 'POST', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$token]),
        fn () => response()->json(['ok' => true]),
    );

    expect($replay->getStatusCode())->toBe(AuthenticateMcp::REFUSAL_STATUS);
})->note('Mutation: move AssertionBurn::burn() out of AuthenticateMcp\'s DB::transaction (or remove the burn ledger\'s mint_hash unique index), and the probe\'s same-bytes insert no longer contends — it completes instead of receiving SQLSTATE 55P03, and the post-commit replay stops answering the ordinary 401. Debt row bfc-mcp-concurrent-presentation-race.');

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
