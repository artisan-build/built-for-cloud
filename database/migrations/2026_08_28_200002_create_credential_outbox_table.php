<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * The transactional outbox (D8 adjustment 3, SEC-V3-09): one row per
 * lifecycle event, inserted in the SAME transaction as the audit row and
 * the state transition, consumed AFTER commit, idempotently.
 *
 * A separate table rather than a deliverable flag on the audit row: the
 * audit row is append-only by construction, and delivery state
 * (claimed_at, attempts, delivered_at) is mutable bookkeeping that must
 * not live on an immutable record.
 *
 * `dedup_key` is UNIQUE and defaults to the audit event id — one delivery
 * per event. It is a free string so later PRs can key on external event
 * ids (the SEC-V3-05 integration machinery) without a schema change.
 *
 * `delivered_recipients` tracks delivery PER RECIPIENT (address ->
 * delivered-at), written immediately after each successful send, so a
 * partial failure (issuer delivered, holder's send threw) retries only the
 * recipients not yet marked. The send and its marker are still two writes:
 * a crash between them re-sends to that ONE recipient — the honest
 * at-least-once window this design accepts.
 *
 * `claim_token` is the ownership fence: each claim writes a fresh token,
 * and every later write for the row (markers, release, completion) is
 * conditioned on it, so a stale owner whose claim expired and was taken
 * over cannot clobber the new owner's markers or claim state.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('credential_outbox', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->uuid('audit_event_id')->index();
            $table->string('dedup_key')->unique();
            $table->unsignedInteger('attempts')->default(0);
            $table->timestamp('claimed_at')->nullable();
            $table->uuid('claim_token')->nullable();
            $table->timestamp('delivered_at')->nullable()->index();
            $table->json('delivered_recipients')->nullable();
            $table->string('last_error')->nullable();
            $table->timestamp('created_at')->nullable();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('credential_outbox');
    }
};
