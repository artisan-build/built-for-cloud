<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Console\AssertionBurn;
use ArtisanBuild\BuiltForCloud\Console\ConsoleEntryRefusalReason;
use ArtisanBuild\BuiltForCloud\Exceptions\ConsoleEntryRefused;
use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use RuntimeException;

uses(RefreshDatabase::class);

// ─── The single-use burn ────────────────────────────────────────────────────

it('refuses a genuine second presentation of the same assertion, because the mint id is spent', function (): void {
    $assertion = consoleAssertionFor();

    AssertionBurn::burn($assertion, CarbonImmutable::now());

    // The SAME mint, presented again — a replay, not a second mint.
    try {
        AssertionBurn::burn($assertion, CarbonImmutable::now());
        $this->fail('The second burn was accepted.');
    } catch (ConsoleEntryRefused $refused) {
        expect($refused->reason)->toBe(ConsoleEntryRefusalReason::Replayed)
            ->and($refused->assertionId)->toBe($assertion->id);
    }

    expect(AssertionBurn::query()->count())->toBe(1);
});

it('length-delimits the burn key, so two different issuer and mint pairs cannot hash alike', function (): void {
    // Without the lengths, one issuer's suffix and the next mint id's
    // prefix concatenate to the same string, and a collision here would
    // refuse a GENUINE assertion as a replay of somebody else's. Only
    // one issuer is trusted in v1 (D18), so this is a property of the
    // key rather than a reachable flow, and it is asserted as one.
    expect(AssertionBurn::mintHash('https://a.test', 'bc'))
        ->not->toBe(AssertionBurn::mintHash('https://a.testb', 'c'))
        ->and(AssertionBurn::mintHash('https://a.test', 'm1'))
        ->toBe(AssertionBurn::mintHash('https://a.test', 'm1'));
});

it('keys the burn on a unique index, which is what makes it atomic', function (): void {
    // The index is the check. A read-then-write would leave exactly the
    // window single-use exists to close.
    expect(Schema::hasTable('bfc_console_assertion_burns'))->toBeTrue();

    $indexes = collect(Schema::getIndexes('bfc_console_assertion_burns'))
        ->filter(fn (array $index): bool => $index['unique'] === true)
        ->flatMap(fn (array $index): array => $index['columns'])
        ->all();

    expect($indexes)->toContain('mint_hash');
});

it('rolls the burn back with the redemption, so the two commit or fail together', function (): void {
    // The genuine race cannot be driven in-process on sqlite (see the
    // mutation-debt row for bfc#pr4). What CAN be driven, and is the
    // property the race rests on, is that the burn row lives in the
    // CALLER'S transaction: a redemption that fails after the burn must
    // leave no spent mint behind.
    //
    // EVERY ASSERTION BELOW LOOKS AT STATE. A test that asserted only
    // that the exception propagated would stay green with the
    // transaction removed entirely — a test named for the atomicity
    // guarantee that could not detect its absence.
    $assertion = consoleAssertionFor();

    try {
        DB::transaction(function () use ($assertion): void {
            AssertionBurn::burn($assertion, CarbonImmutable::now());

            throw new RuntimeException('a downstream step that is down');
        });
        $this->fail('The failing redemption propagated no exception.');
    } catch (RuntimeException) {
    }

    // The burn rolled back with the redemption…
    expect(AssertionBurn::query()->count())->toBe(0);

    // …and because the mint was never spent, a later presentation of the
    // SAME assertion is not a replay. That is the direction that makes
    // this safe rather than merely tidy, and it is also what proves the
    // row is genuinely absent rather than merely uncounted.
    AssertionBurn::burn($assertion, CarbonImmutable::now());

    expect(AssertionBurn::query()->count())->toBe(1);
});

// ─── Housekeeping ───────────────────────────────────────────────────────────

it('sits exactly on the prune boundary: one second inside keeps a burn row, one second past drops it', function (): void {
    // The boundary is the assertion's own life plus the margin, and the
    // margin points ONE WAY on purpose: a row dropped while its
    // assertion could still be presented would UN-SPEND a mint. An
    // earlier revision travelled 100s against a 150s boundary, so the
    // constant could have been almost any value and the test would
    // still have passed. This sits on it from both sides.
    $start = CarbonImmutable::parse('2026-08-29T12:00:00+00:00');
    // consoleAssertionFor() mints `exp` 90 seconds after `iat`.
    $boundary = 90 + AssertionBurn::PRUNE_MARGIN_SECONDS;

    $this->travelTo($start);

    AssertionBurn::burn(consoleAssertionFor(), CarbonImmutable::now());

    $spent = AssertionBurn::query()->sole()->mint_id;

    // ON the boundary: still inside the margin, still kept.
    $this->travelTo($start->addSeconds($boundary));

    AssertionBurn::burn(consoleAssertionFor(), CarbonImmutable::now());
    AssertionBurn::prune(CarbonImmutable::now());

    expect(AssertionBurn::query()->pluck('mint_id')->all())->toContain($spent);

    // One second past it: the row can no longer change any answer.
    $this->travelTo($start->addSeconds($boundary + 1));

    AssertionBurn::burn(consoleAssertionFor(), CarbonImmutable::now());
    AssertionBurn::prune(CarbonImmutable::now());

    expect(AssertionBurn::query()->pluck('mint_id')->all())->not->toContain($spent)
        // …and the rows still inside their own windows are untouched.
        ->and(AssertionBurn::query()->count())->toBe(2);
});
