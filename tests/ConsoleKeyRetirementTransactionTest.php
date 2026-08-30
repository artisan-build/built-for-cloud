<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\RetireConsoleKey;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKey;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyring;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;

/**
 * The retirement's transaction guard, driven for real.
 *
 * **Deliberately NOT `RefreshDatabase`.** That trait wraps every test it
 * touches in a transaction, so `DB::transactionLevel()` would be 1 and
 * the case under test would be unreachable — which is exactly how the
 * first version of this check came to be a reflection scan over the
 * action's source, passing for a weaker reason than its title claimed.
 * Migrations are run per test instead ({@see beforeEach} below), so the
 * ring EXISTS and the key can be read back afterwards; that read is the
 * half a source inspection could never perform.
 *
 * WHAT IT PINS. The action refuses before it touches the database at
 * all. Without that check the recorder's own guard is the first one
 * reached, and by then `retired_at` is already saved: the key stops
 * verifying, the caller sees a failure, and no retirement event exists
 * anywhere — the inversion of the property the audit is for.
 */
beforeEach(function (): void {
    // No RefreshDatabase, so nothing has created the schema. Testbench
    // rebuilds the application (and with it the in-memory database) per
    // test, so this leaves nothing behind for the next one.
    $this->artisan('migrate');
});

it('refuses to retire outside a database transaction, leaving the key verifying', function (): void {
    // The precondition the whole test rests on. Asserted rather than
    // assumed: under a wrapping transaction this would be 1 and
    // everything below would pass for the wrong reason.
    expect(DB::transactionLevel())->toBe(0);

    $secret = consoleKeypair();

    ConsoleKey::query()->create([
        'key_id' => 'k1',
        'public_key' => ConsoleKeyring::normalizePublicKey($secret->getPublicKey()->toHexString()),
        'activated_at' => CarbonImmutable::now()->subHour(),
    ]);

    ConsoleKey::query()->create([
        'key_id' => 'k2',
        'public_key' => ConsoleKeyring::normalizePublicKey(consoleKeypair()->getPublicKey()->toHexString()),
        'activated_at' => CarbonImmutable::now()->subHour(),
    ]);

    expect(fn (): mixed => app(RetireConsoleKey::class)('k1', AuditActor::cliOperator()))
        ->toThrow(LogicException::class, 'transaction');

    // THE HALF A SOURCE INSPECTION CANNOT DO: the key is untouched. A
    // guard that fired only once the recorder was reached would have
    // saved `retired_at` before throwing, and this row would be retired
    // with no event naming it.
    $key = ConsoleKey::query()->where('key_id', 'k1')->sole();

    expect($key->retired_at)->toBeNull()
        ->and($key->isActiveAt(CarbonImmutable::now()))->toBeTrue()
        ->and(array_map(
            static fn (ConsoleKey $active): string => $active->key_id,
            (new ConsoleKeyring)->active(),
        ))->toBe(['k1', 'k2'])
        // And no audit row of any kind was written, which is the other
        // way the pair could have come apart.
        ->and(CredentialAuditEvent::query()->count())->toBe(0);
});

it('refuses an already-retired key outside a transaction too, so the idempotent path cannot slip past the guard', function (): void {
    // The early return for an already-retired key writes nothing, so it
    // is the one path that could plausibly be argued out of the guard.
    // It is not: the guard runs before any read, so this path answers
    // the same. Anything else would make "when is a transaction
    // required" depend on state the caller cannot see.
    expect(DB::transactionLevel())->toBe(0);

    ConsoleKey::query()->create([
        'key_id' => 'k1',
        'public_key' => ConsoleKeyring::normalizePublicKey(consoleKeypair()->getPublicKey()->toHexString()),
        'activated_at' => CarbonImmutable::now()->subHour(),
        'retired_at' => CarbonImmutable::now()->subMinute(),
    ]);

    expect(fn (): mixed => app(RetireConsoleKey::class)('k1', AuditActor::cliOperator()))
        ->toThrow(LogicException::class, 'transaction');

    expect(CredentialAuditEvent::query()->count())->toBe(0);
});
