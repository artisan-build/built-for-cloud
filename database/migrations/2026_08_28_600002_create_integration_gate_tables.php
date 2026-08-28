<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * The SEC-V3-05 ordering gate: idempotency alone cannot order events, so
 * each integration event carries a namespace, a stable event id, and a
 * monotonic entitlement version — and the instance transactionally ignores
 * anything not newer than the latest accepted version per (namespace,
 * external subject).
 *
 * `integration_entitlements` holds that latest accepted version — the
 * gate's lock point. `integration_events` records every event id ever
 * decided (applied or ignored) so a replay answers idempotently. Both
 * tables are EVENT-KIND GENERIC: the offboarding verb (a later PR) plugs
 * its own kind into the same rows.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('integration_entitlements', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('integration_namespace');
            $table->string('external_subject');
            $table->unsignedBigInteger('entitlement_version');
            $table->timestamps();

            $table->unique(['integration_namespace', 'external_subject']);
        });

        Schema::create('integration_events', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('integration_namespace');
            $table->string('event_id');
            $table->string('external_subject');
            $table->string('event_kind');
            $table->unsignedBigInteger('entitlement_version');
            $table->boolean('applied');
            $table->string('invitation_id', 36)->nullable();
            $table->timestamps();

            $table->unique(['integration_namespace', 'event_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('integration_events');
        Schema::dropIfExists('integration_entitlements');
    }
};
