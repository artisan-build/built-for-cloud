<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * The app-action stream's transactional outbox (Console PRD D17): one row
 * per event, inserted in the SAME transaction as the event and the action
 * it announces.
 *
 * A separate table rather than a flag on the event row, for the reason
 * the credential outbox already gives: the event row is append-only by
 * construction, and delivery state is mutable bookkeeping that must not
 * live on an immutable record.
 *
 * `dedup_key` is UNIQUE and defaults to the event id. That index is the
 * whole of "exactly one event per action": a second emission of the same
 * logical action fails this insert and takes the transaction with it.
 *
 * WHAT IS NOT HERE, and why. The credential outbox carries `attempts`,
 * `claimed_at`, `claim_token`, `delivered_at`, `delivered_recipients`
 * and `last_error`, because a drainer writes every one of them. This
 * stream has no consumer in this release — no read transport, no
 * notification, nothing vendor-side — so those columns would be six
 * promises about delivery bookkeeping that no code keeps. They arrive
 * with the consumer that needs them, in its own migration.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('bfc_app_action_outbox', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->uuid('event_id')->index();
            $table->string('dedup_key')->unique();
            $table->timestamp('created_at')->nullable();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('bfc_app_action_outbox');
    }
};
