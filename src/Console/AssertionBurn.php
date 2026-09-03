<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

use ArtisanBuild\BuiltForCloud\Exceptions\ConsoleEntryRefused;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ConsoleEnter;
use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\UniqueConstraintViolationException;

/**
 * THE SINGLE-USE BURN (Console PRD D12): one row per mint identifier
 * this deployment has redeemed, and a unique index that makes a second
 * redemption impossible rather than unlikely.
 *
 * WHAT MAKES IT ATOMIC, precisely. {@see burn()} does not read and then
 * write — it INSERTS, and lets the unique index decide. A check-then-
 * insert would leave the window this exists to close: two presentations
 * of the same assertion arriving together would both read "not spent",
 * both proceed, and both mint a session. The index is evaluated by the
 * database inside the transaction, so exactly one insert survives and
 * every other one raises a uniqueness violation. **A replay is refused
 * because the jti is spent, not because something later noticed.**
 *
 * The insert lives in the CALLER'S redeeming transaction — the same
 * transaction that mints the session at {@see ConsoleEnter}, and the
 * one that burns, lock-checks and publishes at
 * {@see AuthenticateMcp} — so the burn and the principal it pays for
 * commit together or not at all. That direction matters both ways: a
 * redemption that fails after the burn does not spend the mint (the
 * row rolls back with it), and a burn that loses the race takes the
 * redemption down with it.
 *   Pinned by `tests/ConsoleEnterTest.php` — "refuses a genuine second
 *   presentation of the same assertion, because the mint id is spent",
 *   "rolls the burn back with the redemption, so the two commit or fail
 *   together", "keys the burn on a unique index, which is what makes it
 *   atomic" and "length-delimits the burn key, so two different issuer
 *   and mint pairs cannot hash alike".
 *
 * THE RACE IS EXERCISED, ON ONE LANE ONLY. The ordinary suite runs on
 * sqlite, which serializes writers in-process: the citations above
 * drive the SEQUENTIAL replay and the shared-transaction property the
 * race rests on — not the interleaving itself. The `pgsql` group adds
 * the two-connection interleaving on a driver with real row locking,
 * at this table's unique index and through BOTH doors that burn — the
 * enter door's transaction and the MCP middleware's own — so a
 * rewrite of {@see burn()} as check-then-insert reds that lane rather
 * than passing silently. The concurrent claim is only as strong as
 * the lane that runs it: the group is skipped wherever PostgreSQL is
 * not configured, and a deployment that never runs it holds the
 * sequential guarantees only. A mutation-debt row keeps the sweep
 * obligation open.
 *   Pinned by `tests/PostgresConsoleRaceTest.php` — "serializes two
 *   inserts for one assertion at the unique burn index" and
 *   "serializes concurrent presentation through AuthenticateMcp own
 *   transaction".
 *
 * IDENTITY IS A DIGEST, for the reason {@see DelegatedActor} states at
 * length: `jti` is only meaningful inside the issuer that minted it, and
 * a composite unique index over two text columns is exactly as
 * case-sensitive as the database's collation happens to be — which on
 * MySQL's common default it is not. Two mint ids differing only in case
 * would then share one row, and the second real assertion would be
 * refused as a replay of the first. sha256 over a LENGTH-DELIMITED
 * encoding is byte-exact on every driver.
 *
 * ROWS ARE PRUNED, and they are the only rows in this package that are.
 * A burn row is useful exactly until the assertion it names expires:
 * past `exp` the verifier refuses the token before the burn is ever
 * consulted, so an older row can never change an answer. {@see prune()}
 * deletes them after a margin, and the doors that write burns are the
 * doors that call it — the enter endpoint after a successful entry,
 * `AuthenticateMcp` after a successful authentication — each on its
 * SUCCESS path only, which is also the only path that writes one, so
 * the table's growth and its pruning are driven by the same events and
 * an attacker can force neither. The margin points one way on purpose:
 * a row dropped while its assertion could still be presented would
 * UN-SPEND a mint, so the boundary is driven from BOTH sides rather
 * than from comfortably inside it.
 *   Pinned by `tests/ConsoleEnterTest.php` — "sits exactly on the prune boundary: one second inside keeps a burn row, one second past drops it".
 *
 * ONE REFUSAL DELIBERATELY DOES NOT SPEND A MINT. A contained actor's
 * presentation throws inside the redeeming transaction — at either
 * door, the enter endpoint's or the MCP middleware's — so the burn
 * rolls back with it and that assertion stays presentable until its
 * TTL runs out — every presentation refused, every one audited as
 * `actor_deactivated` (rendered 403 at the enter door, 401 at the MCP
 * door; the reason code is the same at both). Spending it instead
 * would make the second attempt audit as `replayed`, which asserts
 * the token was already REDEEMED. It was not, and an operator reading
 * an offboarded human's attempts to get back in would draw exactly
 * the wrong conclusion. This table records mints this deployment
 * redeemed; the audit stream records presentations, and it records
 * all of them.
 *   Pinned by `tests/ConsoleEnterTest.php` — "leaves a contained actor's mint unspent, so every attempt audits as containment".
 *   Pinned by `tests/AuthenticateMcpTest.php` — "keeps the contained
 *   actor handoff but rolls back its burn and principal".
 */
final class AssertionBurn extends Model
{
    /**
     * How long past an assertion's own expiry a burn row is kept. It
     * buys nothing security-wise — the verifier has refused the token
     * since `exp` — and exists so that clock jitter between the row and
     * the pruning read can never delete a row still inside its window.
     */
    public const int PRUNE_MARGIN_SECONDS = 60;

    protected $table = 'bfc_console_assertion_burns';

    public $timestamps = false;

    /**
     * @var list<string>
     */
    protected $fillable = [
        'mint_hash',
        'issuer',
        'mint_id',
        'expires_at',
        'redeemed_at',
    ];

    /**
     * The byte-exact identity of an issuer + mint id pair.
     *
     * LENGTH-DELIMITED before hashing so that `('ab', 'c')` and
     * `('a', 'bc')` cannot collide: without the lengths, one issuer's
     * suffix and another's mint id prefix would hash alike, and a
     * collision here refuses a genuine assertion as a replay.
     */
    public static function mintHash(string $issuer, string $mintId): string
    {
        return hash('sha256', strlen($issuer).':'.$issuer.':'.strlen($mintId).':'.$mintId);
    }

    /**
     * Spend a mint, or refuse because it is already spent.
     *
     * MUST be called inside the redeeming transaction. It writes and
     * never reads: the unique index is the check, and the insert is the
     * act.
     *
     * The catch is narrow and its narrowness is deliberate.
     * `mint_hash` carries the table's ONLY unique index, so a
     * uniqueness violation here can be nothing but a second
     * presentation of this assertion — while a connection drop, a
     * permission failure or a full disk keeps travelling as the server
     * error it is, rather than being reported to an operator as a
     * replay of a token they presented once.
     *
     * Nothing re-reads the table to confirm, and nothing may: on
     * PostgreSQL a uniqueness violation aborts every later statement in
     * the transaction (SQLSTATE 25P02), so a confirming read would
     * itself throw and turn a clean refusal into a 500.
     *
     * @throws ConsoleEntryRefused when this mint has already been redeemed
     */
    public static function burn(Assertion $assertion, CarbonInterface $now): self
    {
        try {
            /** @var self */
            return self::query()->create([
                'mint_hash' => self::mintHash($assertion->issuer, $assertion->id),
                'issuer' => $assertion->issuer,
                'mint_id' => $assertion->id,
                'expires_at' => $assertion->expiresAt,
                'redeemed_at' => $now,
            ]);
        } catch (UniqueConstraintViolationException $spent) {
            throw ConsoleEntryRefused::because(
                ConsoleEntryRefusalReason::Replayed,
                $assertion->id,
                $spent,
            );
        }
    }

    /**
     * Drop burn rows whose assertions expired more than
     * {@see PRUNE_MARGIN_SECONDS} ago, and report how many.
     *
     * Called AFTER the redeeming transaction commits and best-effort:
     * housekeeping must never fail an entry the operator already earned,
     * and a delete inside that transaction would lengthen the one
     * transaction a concurrent replay contends with.
     */
    public static function prune(CarbonInterface $now): int
    {
        return self::query()
            ->where('expires_at', '<', CarbonImmutable::instance($now)->subSeconds(self::PRUNE_MARGIN_SECONDS))
            ->delete();
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'expires_at' => 'immutable_datetime',
            'redeemed_at' => 'immutable_datetime',
        ];
    }
}
