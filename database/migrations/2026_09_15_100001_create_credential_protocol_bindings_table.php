<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\CredentialAlgorithm;
use ArtisanBuild\BuiltForCloud\CredentialMaterialRole;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('credential_protocol_bindings', function (Blueprint $table): void {
            $table->foreignUuid('credential_id')->primary()->constrained('credentials')->cascadeOnDelete();
            $table->string('app_purpose');
            $table->string('installation_ref');
            $table->string('application_ref');
            $table->string('audience');
            $table->enum('algorithm', array_column(CredentialAlgorithm::cases(), 'value'));
            $table->enum('material_role', array_column(CredentialMaterialRole::cases(), 'value'));
            $table->char('scope_hash', 64)->index();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('credential_protocol_bindings');
    }
};
