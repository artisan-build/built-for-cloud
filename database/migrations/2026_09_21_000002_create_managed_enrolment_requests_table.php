<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * The durable idempotency ledger behind the three managed-enrolment
     * verbs: enrolment, client-secret rotation and disconnect each
     * record their caller UUID, the non-secret request facts and the
     * committed outcome, so a lost-response retry replays exactly and a
     * reused UUID with different facts is a conflict, never a second
     * mutation. Rows are RETAINED across disconnect — every later
     * enrolment needs a fresh UUID.
     */
    public function up(): void
    {
        Schema::create('bfc_managed_enrolment_requests', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('kind', 24);
            $table->string('issuer');
            $table->string('connection_id');
            $table->string('installation_id');
            $table->string('organization_id')->nullable();
            $table->string('authority_base_url', 2048)->nullable();
            $table->unsignedBigInteger('expected_generation');
            $table->unsignedBigInteger('expected_client_secret_generation')->nullable();
            $table->char('secret_retry_digest', 64)->nullable();
            $table->json('committed_response')->nullable();
            $table->timestamp('committed_at')->nullable();
            $table->uuid('managed_transition_id')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('bfc_managed_enrolment_requests');
    }
};
