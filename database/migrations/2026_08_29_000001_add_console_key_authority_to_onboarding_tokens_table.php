<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Key-custody authority on a claim code (Console PRD D12, rework B1).
 *
 * Before this column, ANY claim code could carry a countersigning-key
 * delivery — including the routine `scope=consume` code an operator
 * hands a low-privilege integration. Filing a console key installs a
 * signing authority that can mint delegated-ADMIN entry into this
 * deployment, so that was an escalation from "may consume an API" to
 * "may enter as admin, repeatedly, from anywhere".
 *
 * The authority is therefore explicit, server-set at issue time by an
 * admin-gated surface, and NOT mass-assignable — the same discipline
 * `api_tokens.rotated_at` uses, and for the same reason: a flag that
 * request input can set is not an authority.
 *
 * It is also SINGLE USE, independently of the code's burn mode. Under
 * `first_use` a code stays presentable until the durable it minted is
 * first used, so without this stamp one authorized code could file a
 * second key under a fresh key id — and each filed key is its own
 * standing admin-entry authority.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('onboarding_tokens', function (Blueprint $table): void {
            // Whether this code may carry a `console_key` delivery at all.
            // Default false: every code that already exists, and every code
            // issued without asking for this, carries no such authority.
            $table->boolean('console_key_authority')->default(false);

            // When the authority was spent. Non-null means this code has
            // already filed its one key and will not file another.
            $table->timestamp('console_key_filed_at')->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('onboarding_tokens', function (Blueprint $table): void {
            $table->dropColumn(['console_key_authority', 'console_key_filed_at']);
        });
    }
};
