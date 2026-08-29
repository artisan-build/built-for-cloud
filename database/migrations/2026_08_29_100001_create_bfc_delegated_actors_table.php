<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * The SHADOW ACTOR table (Console PRD §4.3): one row per delegated human
 * this deployment has ever admitted, identified by ISSUER + SUBJECT.
 *
 * It is deliberately NOT a `users` table and must never become one. There
 * is no password column, no remember-token column, and no column any
 * credential could ever point at: nothing in this package offers a login
 * path to one of these rows, and the `bfc-console` user provider refuses
 * every credential-shaped lookup outright. A row here is an ATTRIBUTION
 * REFERENT and a stable identity — never an authentication secret, and
 * never the live authorization-claim store (see the `last_handoff_*`
 * columns below).
 *
 * IDENTITY IS A DIGEST, NOT A COLLATED COMPARISON. The unique key is
 * `identity_hash`: sha256 over a LENGTH-DELIMITED encoding of issuer and
 * subject. A composite unique index over the two text columns would be
 * exactly as case- and accent-sensitive as the database's collation
 * happens to be, and MySQL's common default (`utf8mb4_0900_ai_ci`) is
 * neither: subjects `OperatorA` and `operatora` would compare EQUAL, so
 * the second human's handoff would update the first human's row and two
 * distinct principals would share one identity, one role and one audit
 * history. Two subjects that differ by one byte are two humans, and that
 * must not depend on how a DBA configured the server.
 *
 * A per-column binary collation would fix it on MySQL and not port —
 * Postgres has no `utf8mb4_bin`, and sqlite's collation vocabulary is
 * different again. A hex digest is byte-exact on every one of them: the
 * digest is computed in PHP from the raw bytes, and two distinct
 * lower-case hex strings stay distinct even under a case-insensitive
 * collation. The length delimiting is what stops `('ab', 'c')` and
 * `('a', 'bc')` hashing alike.
 *
 * `issuer` and `subject` are still stored, in full, because the audit
 * stream and any operator listing need to read them — they are DATA
 * here, not the key.
 *
 * KEY SHAPE: an ordinary auto-incrementing integer, the same id space
 * `users` occupies, ON PURPOSE. The thing that stops a delegated
 * principal colliding with a local one is the TYPE QUALIFIER the model
 * puts in front of the id (`bfc-console:{id}`), not a lucky choice of a
 * different id space — so the two spaces are left overlapping and the
 * qualifier stays load-bearing, testable, and impossible to drop by
 * accident.
 *
 * RETENTION: these rows are NEVER PRUNED. Every delegated audit
 * attribution the app-action stream writes (Console PRD D17, PR7) points
 * at one of them, so deleting a row orphans attribution history — an
 * audit line that can no longer say who acted. Offboarding sets
 * `deactivated_at` and stops the row authenticating; it does not remove
 * it, and nothing in this package deletes one.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('bfc_delegated_actors', function (Blueprint $table): void {
            $table->id();

            // The identity, byte-exact and collation-independent. See the
            // docblock: this is the unique key, and the two text columns
            // below are the readable copy of what it was computed from.
            $table->char('identity_hash', 64)->unique();

            // The issuer that vouched for this human, and that issuer's
            // own opaque identifier for them. `subject` is only meaningful
            // inside the issuer that minted it, which is why both are
            // inside the digest. (Console PRD D18 trusts exactly one
            // issuer in v1; the composite identity is what keeps that a
            // configuration fact rather than a schema assumption.)
            $table->string('issuer', 255);
            $table->string('subject', 255);

            // THE LAST HANDOFF'S CLAIMS — named for exactly that, because
            // they are NOT the claims of any live session. PRD D8 makes
            // role and display claims per-mint and never cached beyond the
            // session that carried them, and this row is shared by every
            // live session for this subject: a later handoff arriving as
            // `admin` would otherwise silently promote a session that
            // entered as `member`. The claims a request acts under are
            // SESSION-BOUND ({@see ConsoleSession}); these columns exist
            // so an operator listing and the audit stream can say what the
            // most recent entry looked like, and nothing authorizes or
            // attributes from them.
            //
            // `last_handoff_display_name` and `last_handoff_on_behalf_of`
            // are ISSUER-SUPPLIED FREE TEXT. They are bounded in length
            // and free of control characters because the verifier refused
            // anything else — that is all. They are NOT sanitized HTML and
            // whatever renders them must escape for its own context.
            // Widths match the verifier's own bounds
            // (AssertionVerifier::MAX_DISPLAY_LENGTH), so a claim that
            // passed verification always fits.
            $table->string('last_handoff_display_name', 120);
            $table->string('last_handoff_on_behalf_of', 120)->nullable();
            $table->string('last_handoff_role', 16);

            // Offboarding deactivates; it never deletes (see RETENTION
            // above). A deactivated row keeps answering for attribution
            // and stops resolving as a principal.
            $table->timestamp('deactivated_at')->nullable();

            // `updated_at` is the last handoff: the upsert touches the
            // row on every entry, so no separate "last seen" column is
            // carried.
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('bfc_delegated_actors');
    }
};
