<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * THE SINGLE-USE BURN LEDGER (Console PRD D12): one row per console
 * assertion this deployment has redeemed.
 *
 * THE UNIQUE INDEX IS THE FEATURE. `POST /bfc/console/enter` does not
 * read this table before it writes: it inserts, inside the same
 * transaction that mints the delegated session, and lets the index
 * decide. A check-then-insert would leave exactly the window single-use
 * exists to close — two presentations arriving together would both read
 * "not spent" and both mint. With the index, one insert survives and
 * every other raises a uniqueness violation, so a replay is refused
 * BECAUSE the mint id is spent rather than because something later
 * noticed.
 *
 * IDENTITY IS A DIGEST, NOT A COLLATED COMPARISON — the same reasoning
 * `bfc_delegated_actors` carries, and it lands the other way round here.
 * A `jti` is only meaningful inside the issuer that minted it, so the
 * identity is issuer + mint id; a composite unique index over the two
 * text columns would be as case-insensitive as the database happens to
 * be (MySQL's common `utf8mb4_0900_ai_ci` is), and two mint ids
 * differing only in case would then share a row — so the SECOND genuine
 * assertion would be refused as a replay of the first, locking a real
 * operator out. `mint_hash` is sha256 over a length-delimited encoding
 * of the pair, computed in PHP from the raw bytes, and is byte-exact on
 * every driver.
 *
 * `issuer` and `mint_id` are stored in full alongside it because an
 * operator investigating a refusal needs to read them; they are DATA
 * here, not the key.
 *
 * RETENTION — and this is the one table in the package that is pruned.
 * A row is useful exactly until the assertion it names expires: past
 * `exp` the verifier refuses the token before the burn is consulted, so
 * an older row cannot change any answer. The enter endpoint prunes past
 * that (plus a margin) after each successful entry, which is also the
 * only event that writes a row — so growth and pruning are driven by
 * the same events, and neither is reachable without a valid, signed,
 * unexpired assertion.
 *
 * NO SECRET IS STORED. A `jti` is a mint identifier, not a credential:
 * it is worthless without the signed token that carries it, and that
 * token is never persisted anywhere.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('bfc_console_assertion_burns', function (Blueprint $table): void {
            $table->id();

            // The identity, byte-exact and collation-independent, and
            // the reason this table works at all.
            $table->char('mint_hash', 64)->unique();

            // The readable copy of what the digest was computed from.
            // Widths match the verifier's own bounds
            // (AssertionVerifier::MAX_IDENTITY_LENGTH / MAX_ID_LENGTH),
            // so a claim that passed verification always fits.
            $table->string('issuer', 255);
            $table->string('mint_id', 64);

            // The assertion's own expiry, which is what makes this table
            // prunable, and the moment it was spent.
            $table->timestamp('expires_at')->index();
            $table->timestamp('redeemed_at');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('bfc_console_assertion_burns');
    }
};
