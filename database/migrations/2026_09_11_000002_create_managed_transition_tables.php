<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('bfc_managed_transitions', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('initiated_by_user_id', 64);
            $table->string('direction', 16);
            $table->string('status', 16);
            $table->string('active_installation_slot')
                ->nullable()
                ->storedAs("CASE WHEN status IN ('acknowledged', 'abandoned') THEN NULL ELSE installation_id END");
            $table->string('issuer');
            $table->string('connection_id');
            $table->string('organization_id');
            $table->string('installation_id');
            $table->string('authority_base_url', 2048);
            $table->string('authority_ca_bundle', 2048)->nullable();
            $table->string('client_credential_reference');
            $table->string('mode_before', 16);
            $table->string('mode_after', 16);
            $table->unsignedBigInteger('generation_before');
            $table->unsignedBigInteger('generation_after');
            $table->string('transition_request_id');
            $table->string('transition_id')->nullable();
            $table->unsignedBigInteger('roster_version')->nullable();
            $table->string('roster_cutoff_at', 64)->nullable();
            $table->unsignedBigInteger('roster_total')->nullable();
            $table->unsignedSmallInteger('roster_pages_received')->default(0);
            $table->unsignedInteger('roster_members_received')->default(0);
            $table->text('next_roster_cursor')->nullable();
            $table->string('local_commit_receipt')->nullable();
            $table->string('authority_acknowledged_at', 64)->nullable();
            $table->longText('prepare_request_body');
            $table->char('prepare_body_digest', 64);
            $table->string('stage_idempotency_key')->nullable();
            $table->longText('stage_request_body')->nullable();
            $table->char('stage_body_digest', 64)->nullable();
            $table->string('ack_idempotency_key')->nullable();
            $table->longText('ack_request_body')->nullable();
            $table->char('ack_body_digest', 64)->nullable();
            $table->string('abandon_idempotency_key')->nullable();
            $table->longText('abandon_request_body')->nullable();
            $table->char('abandon_body_digest', 64)->nullable();
            $table->timestamps();

            $table->unique('active_installation_slot', 'bfc_transition_active_slot_unique');
            $table->unique(
                ['installation_id', 'direction', 'transition_request_id'],
                'bfc_transition_request_scope_unique',
            );
            $table->unique(
                ['installation_id', 'transition_id'],
                'bfc_transition_authority_id_unique',
            );
        });

        Schema::create('bfc_managed_transition_roster_members', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->uuid('managed_transition_id');
            $table->unsignedInteger('ordinal');
            $table->unsignedSmallInteger('page_number');
            $table->unsignedSmallInteger('page_position');
            $table->string('scalpels_id');
            $table->string('membership_status', 16);
            $table->string('role', 16);
            $table->string('display_name');
            $table->string('contact_email');
            $table->boolean('contact_email_verified');
            $table->timestamp('created_at')->nullable();

            $table->foreign('managed_transition_id', 'bfc_transition_roster_parent_fk')
                ->references('id')->on('bfc_managed_transitions')->cascadeOnDelete();
            $table->unique(
                ['managed_transition_id', 'scalpels_id'],
                'bfc_transition_roster_subject_unique',
            );
            $table->unique(
                ['managed_transition_id', 'ordinal'],
                'bfc_transition_roster_ordinal_unique',
            );
        });

        Schema::create('bfc_managed_transition_roster_cursors', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->uuid('managed_transition_id');
            $table->char('cursor_hash', 64);
            $table->text('cursor');
            $table->unsignedSmallInteger('first_seen_page');
            $table->timestamp('created_at')->nullable();

            $table->foreign('managed_transition_id', 'bfc_transition_cursor_parent_fk')
                ->references('id')->on('bfc_managed_transitions')->cascadeOnDelete();
            $table->unique(
                ['managed_transition_id', 'cursor_hash'],
                'bfc_transition_cursor_unique',
            );
        });

        Schema::create('bfc_managed_transition_mappings', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->uuid('managed_transition_id');
            $table->unsignedInteger('ordinal');
            $table->string('scalpels_id')->nullable();
            $table->string('local_kind', 16)->nullable();
            $table->string('local_id', 64)->nullable();
            $table->string('role', 16)->nullable();
            $table->string('disposition', 32);
            $table->string('final_email')->nullable();
            $table->timestamps();

            $table->foreign('managed_transition_id', 'bfc_transition_mapping_parent_fk')
                ->references('id')->on('bfc_managed_transitions')->cascadeOnDelete();
            $table->unique(
                ['managed_transition_id', 'ordinal'],
                'bfc_transition_mapping_ordinal_unique',
            );
            $table->unique(
                ['managed_transition_id', 'scalpels_id'],
                'bfc_transition_mapping_subject_unique',
            );
            $table->unique(
                ['managed_transition_id', 'local_kind', 'local_id'],
                'bfc_transition_mapping_local_unique',
            );
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('bfc_managed_transition_mappings');
        Schema::dropIfExists('bfc_managed_transition_roster_cursors');
        Schema::dropIfExists('bfc_managed_transition_roster_members');
        Schema::dropIfExists('bfc_managed_transitions');
    }
};
