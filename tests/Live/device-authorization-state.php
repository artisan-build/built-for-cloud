<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;

define('TESTBENCH_WORKING_PATH', dirname(__DIR__, 2));

require __DIR__.'/../../vendor/autoload.php';

$app = require __DIR__.'/../../vendor/orchestra/testbench-core/laravel/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();
$input = json_decode(stream_get_contents(STDIN), true, flags: JSON_THROW_ON_ERROR);

if (! is_array($input) || ! is_string($input['operation'] ?? null)) {
    throw new RuntimeException('The device authorization state operation is malformed.');
}

if ($input['operation'] === 'expire') {
    $deviceCode = $input['device_code'] ?? null;

    if (! is_string($deviceCode) || preg_match('/\A[A-Za-z0-9_-]{43}\z/D', $deviceCode) !== 1) {
        throw new RuntimeException('The disposable expiry operation requires one valid device code.');
    }

    $updated = DB::table('credential_authorizations')
        ->where('device_code_hash', hash('sha256', $deviceCode))
        ->whereIn('status', ['pending', 'approved'])
        ->update(['expires_at' => now()->subSecond(), 'updated_at' => now()]);

    if ($updated !== 1) {
        throw new RuntimeException('The disposable expiry operation did not select exactly one live grant.');
    }

    fwrite(STDOUT, "{\"expired\":true}\n");

    return;
}

if ($input['operation'] === 'summary') {
    fwrite(STDOUT, json_encode([
        'authorizations' => DB::table('credential_authorizations')->count(),
        'pending' => DB::table('credential_authorizations')->where('status', 'pending')->count(),
        'approved' => DB::table('credential_authorizations')->where('status', 'approved')->count(),
        'denied' => DB::table('credential_authorizations')->where('status', 'denied')->count(),
        'consumed' => DB::table('credential_authorizations')->where('status', 'consumed')->count(),
        'credentials' => DB::table('credentials')->count(),
    ], JSON_THROW_ON_ERROR)."\n");

    return;
}

if ($input['operation'] === 'device') {
    $deviceCode = $input['device_code'] ?? null;

    if (! is_string($deviceCode) || preg_match('/\A[A-Za-z0-9_-]{43}\z/D', $deviceCode) !== 1) {
        throw new RuntimeException('The disposable detail operation requires one valid device code.');
    }

    $authorization = DB::table('credential_authorizations')
        ->where('device_code_hash', hash('sha256', $deviceCode))
        ->first();

    if (! is_object($authorization)) {
        throw new RuntimeException('The disposable detail operation could not find its grant.');
    }

    fwrite(STDOUT, json_encode([
        'status' => $authorization->status,
        'effective_interval' => $authorization->effective_interval,
        'last_polled_at' => $authorization->last_polled_at,
        'audit_events' => DB::table('credential_audit_events')
            ->where('credential_authorization_id', $authorization->id)
            ->count(),
    ], JSON_THROW_ON_ERROR)."\n");

    return;
}

if ($input['operation'] === 'device-exchange') {
    $deviceCode = $input['device_code'] ?? null;

    if (! is_string($deviceCode) || preg_match('/\A[A-Za-z0-9_-]{43}\z/D', $deviceCode) !== 1) {
        throw new RuntimeException('The disposable exchange detail operation requires one valid device code.');
    }

    $authorization = DB::table('credential_authorizations')
        ->where('device_code_hash', hash('sha256', $deviceCode))
        ->first();

    if (! is_object($authorization)) {
        throw new RuntimeException('The disposable exchange detail operation could not find its grant.');
    }

    fwrite(STDOUT, json_encode([
        'status' => $authorization->status,
        'credential_rows' => is_string($authorization->issued_credential_id)
            ? DB::table('credentials')->where('id', $authorization->issued_credential_id)->count()
            : 0,
    ], JSON_THROW_ON_ERROR)."\n");

    return;
}

if ($input['operation'] === 'device-decision') {
    $deviceCode = $input['device_code'] ?? null;
    $submissionNonce = $input['submission_nonce'] ?? null;

    if (! is_string($deviceCode) || preg_match('/\A[A-Za-z0-9_-]{43}\z/D', $deviceCode) !== 1
        || ! is_string($submissionNonce) || preg_match('/\A[0-9a-f]{64}\z/D', $submissionNonce) !== 1) {
        throw new RuntimeException('The disposable decision detail operation is malformed.');
    }

    $authorization = DB::table('credential_authorizations')
        ->where('device_code_hash', hash('sha256', $deviceCode))
        ->first();

    if (! is_object($authorization)) {
        throw new RuntimeException('The disposable decision detail operation could not find its grant.');
    }

    fwrite(STDOUT, json_encode([
        'status' => $authorization->status,
        'denial_reason' => $authorization->denial_reason,
        'issued_credential_id' => $authorization->issued_credential_id,
        'decision_events' => DB::table('credential_audit_events')
            ->where('credential_authorization_id', $authorization->id)
            ->where('event', LifecycleEventType::CredentialAuthorizationDenied->value)
            ->count(),
        'credential_count' => DB::table('credentials')->count(),
        'submission_nonce_present' => DB::table('bfc_submission_nonces')
            ->where('nonce_hash', hash('sha256', $submissionNonce))
            ->exists(),
    ], JSON_THROW_ON_ERROR)."\n");

    return;
}

if ($input['operation'] === 'managed-authority') {
    $state = $input['state'] ?? null;
    $owner = DB::table('users')->where('email', 'owner@example.test')->first();

    if (! is_object($owner) || ! in_array($state, ['positive', 'inactive', 'local'], true)) {
        throw new RuntimeException('The disposable managed-authority operation is malformed.');
    }

    if ($state === 'positive') {
        $authorityUpdated = DB::table('bfc_authority')
            ->where('key', InstallationAuthority::KEY)
            ->where('mode', AuthorityMode::Standalone->value)
            ->update([
                'mode' => AuthorityMode::Managed->value,
                'generation' => 2,
                'issuer' => 'https://device-live-issuer.example.test',
                'connection_id' => 'device-live-connection',
                'organization_id' => 'device-live-organization',
                'installation_id' => 'install_device_live',
                'authority_base_url' => 'https://device-live-authority.example.test',
                'managed_connection_status' => 'active',
                'managed_connection_generation' => 2,
                'managed_connection_roster_version' => 1,
                'managed_connection_response_sequence' => 1,
                'updated_at' => now(),
            ]);
        $userUpdated = DB::table('users')->where('id', $owner->id)->update([
            'scalpels_issuer' => 'https://device-live-issuer.example.test',
            'scalpels_connection_id' => 'device-live-connection',
            'scalpels_id' => 'device-live-owner',
            'membership_confirmed_at' => now(),
            'membership_checked_at' => now(),
            'membership_response_at' => now(),
            'managed_membership_status' => 'active',
            'managed_membership_role' => 'owner',
            'managed_membership_generation' => 2,
            'managed_membership_roster_version' => 1,
            'managed_membership_response_sequence' => 1,
            'managed_membership_responded_at' => now()->toAtomString(),
            'updated_at' => now(),
        ]);

        if ($authorityUpdated !== 1 || $userUpdated !== 1) {
            throw new RuntimeException('The disposable managed positive was not installed exactly once.');
        }
    } elseif ($state === 'inactive') {
        $updated = DB::table('bfc_authority')
            ->where('key', InstallationAuthority::KEY)
            ->where('mode', AuthorityMode::Managed->value)
            ->where('managed_connection_status', 'active')
            ->update(['managed_connection_status' => 'inactive']);

        if ($updated !== 1) {
            throw new RuntimeException('The disposable managed connection did not become inactive exactly once.');
        }
    } else {
        $authorityUpdated = DB::table('bfc_authority')
            ->where('key', InstallationAuthority::KEY)
            ->where('mode', AuthorityMode::Managed->value)
            ->where('managed_connection_status', 'inactive')
            ->update([
                'mode' => AuthorityMode::Standalone->value,
                'generation' => 3,
                'issuer' => null,
                'connection_id' => null,
                'organization_id' => null,
                'installation_id' => null,
                'authority_base_url' => null,
                'managed_connection_status' => null,
                'managed_connection_generation' => null,
                'managed_connection_roster_version' => null,
                'managed_connection_response_sequence' => null,
                'updated_at' => now(),
            ]);
        $userUpdated = DB::table('users')->where('id', $owner->id)->update([
            'scalpels_issuer' => null,
            'scalpels_connection_id' => null,
            'scalpels_id' => null,
            'membership_confirmed_at' => null,
            'membership_checked_at' => null,
            'membership_response_at' => null,
            'managed_membership_status' => null,
            'managed_membership_role' => null,
            'managed_membership_generation' => null,
            'managed_membership_roster_version' => null,
            'managed_membership_response_sequence' => null,
            'managed_membership_responded_at' => null,
            'updated_at' => now(),
        ]);

        if ($authorityUpdated !== 1 || $userUpdated !== 1) {
            throw new RuntimeException('The disposable local authority was not restored exactly once.');
        }
    }

    fwrite(STDOUT, json_encode(['state' => $state], JSON_THROW_ON_ERROR)."\n");

    return;
}

if ($input['operation'] === 'clear-token-limiters') {
    foreach (['bfc-device-token|127.0.0.1', 'bfc-loopback-token|127.0.0.1', 'bfc-authorization-token-global'] as $key) {
        RateLimiter::clear(md5('bfc-authorization-token'.$key));
    }

    fwrite(STDOUT, "{\"cleared\":true}\n");

    return;
}

if ($input['operation'] === 'clear-decision-limiters') {
    $userIds = DB::table('users')->whereIn('email', ['owner@example.test', 'admin@example.test'])->pluck('id');

    foreach ($userIds as $userId) {
        RateLimiter::clear(md5('bfc-authorization-decision'.'bfc-authorization-decision|'.$userId.'|127.0.0.1'));
    }

    fwrite(STDOUT, "{\"cleared\":true}\n");

    return;
}

if ($input['operation'] === 'reset-effects') {
    $credentialId = $input['credential_id'] ?? null;

    if (! is_string($credentialId) || ! DB::table('credentials')->where('id', $credentialId)->exists()) {
        throw new RuntimeException('The disposable effect reset requires one credential.');
    }

    if (! Schema::hasTable('bfc_device_harness_effects')) {
        Schema::create('bfc_device_harness_effects', function (Blueprint $table): void {
            $table->uuid('credential_id')->primary();
            $table->unsignedInteger('authorize_calls')->default(0);
            $table->unsignedInteger('usage_calls')->default(0);
            $table->unsignedInteger('domain_handler_calls')->default(0);
        });
    }

    DB::table('bfc_device_harness_effects')->delete();
    DB::table('bfc_device_harness_effects')->insert([
        'credential_id' => $credentialId,
        'authorize_calls' => 0,
        'usage_calls' => 0,
        'domain_handler_calls' => 0,
    ]);
    DB::table('credentials')->where('id', $credentialId)->update([
        'last_used_at' => '2000-01-01 00:00:00',
        'client_identity' => null,
        'client_identity_last_seen_at' => null,
    ]);
    RateLimiter::clear('bfc-device-harness-use|'.$credentialId);

    fwrite(STDOUT, "{\"reset\":true}\n");

    return;
}

if ($input['operation'] === 'credential') {
    $flow = $input['flow'] ?? null;

    if (! in_array($flow, ['device', 'loopback'], true)) {
        throw new RuntimeException('The disposable credential lookup requires one closed flow.');
    }

    $credential = DB::table('credential_authorizations')
        ->join('credentials', 'credentials.id', '=', 'credential_authorizations.issued_credential_id')
        ->where('credential_authorizations.flow', $flow)
        ->where('credential_authorizations.status', 'consumed')
        ->orderByDesc('credential_authorizations.consumed_at')
        ->first(['credentials.*']);

    if (! is_object($credential)) {
        throw new RuntimeException('The disposable credential lookup found no exchanged grant.');
    }

    $binding = DB::table('credential_protocol_bindings')->where('credential_id', $credential->id)->first();

    if (! is_object($binding)) {
        throw new RuntimeException('The disposable credential lookup found no exact binding.');
    }

    fwrite(STDOUT, json_encode([
        'credential_id' => $credential->id,
        'purpose' => $credential->purpose,
        'subject_ref' => $credential->subject_ref,
        'user_id' => $credential->user_id,
        'abilities' => json_decode((string) $credential->abilities, true),
        'installation_ref' => $binding->installation_ref,
        'application_ref' => $binding->application_ref,
        'audience' => $binding->audience,
        'algorithm' => $binding->algorithm,
        'material_role' => $binding->material_role,
        'scope_hash' => $binding->scope_hash,
    ], JSON_THROW_ON_ERROR)."\n");

    return;
}

if ($input['operation'] === 'set-credential-dimension') {
    $credentialId = $input['credential_id'] ?? null;
    $dimension = $input['dimension'] ?? null;
    $value = $input['value'] ?? null;
    $credentialColumns = ['purpose', 'subject_ref', 'user_id', 'abilities'];
    $bindingColumns = ['installation_ref', 'application_ref', 'audience', 'algorithm', 'material_role', 'scope_hash'];

    if (! is_string($credentialId) || ! is_string($dimension)
        || (! in_array($dimension, $credentialColumns, true) && ! in_array($dimension, $bindingColumns, true))) {
        throw new RuntimeException('The disposable credential mutation is malformed.');
    }

    if ($dimension === 'abilities') {
        $value = json_encode($value, JSON_THROW_ON_ERROR);
    }

    if ($dimension === 'user_id' && $value === 'first-user') {
        $value = DB::table('users')->orderBy('id')->value('id');
    }

    $table = in_array($dimension, $credentialColumns, true) ? 'credentials' : 'credential_protocol_bindings';
    $key = $table === 'credentials' ? 'id' : 'credential_id';
    $updated = DB::table($table)->where($key, $credentialId)->update([$dimension => $value, 'updated_at' => now()]);

    if ($updated !== 1) {
        throw new RuntimeException('The disposable credential mutation did not select exactly one row.');
    }

    fwrite(STDOUT, "{\"updated\":true}\n");

    return;
}

if ($input['operation'] === 'delete-credential-control') {
    $credentialId = $input['credential_id'] ?? null;

    if (! is_string($credentialId)
        || DB::table('credential_protocol_bindings')->where('credential_id', $credentialId)->exists()
        || DB::table('credentials')->where('id', $credentialId)->delete() !== 1) {
        throw new RuntimeException('The disposable unbound control cleanup was not exact.');
    }

    if (Schema::hasTable('bfc_device_harness_effects')) {
        DB::table('bfc_device_harness_effects')->where('credential_id', $credentialId)->delete();
    }

    RateLimiter::clear('bfc-device-harness-use|'.$credentialId);

    fwrite(STDOUT, "{\"deleted\":true}\n");

    return;
}

if ($input['operation'] === 'create-unbound-bearer') {
    $source = DB::table('credentials')->whereNotNull('id')->orderByDesc('created_at')->first();

    if (! is_object($source)) {
        throw new RuntimeException('The disposable unbound control requires one source credential.');
    }

    $secret = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    $row = (array) $source;
    $row['id'] = (string) Str::uuid();
    $row['secret_hash'] = hash('sha256', $secret);
    $row['last_used_at'] = null;
    $row['client_identity'] = null;
    $row['client_identity_last_seen_at'] = null;
    $row['created_at'] = now();
    $row['updated_at'] = now();
    DB::table('credentials')->insert($row);
    fwrite(STDOUT, json_encode(['credential_id' => $row['id'], 'access_token' => $secret], JSON_THROW_ON_ERROR)."\n");

    return;
}

throw new RuntimeException('The device authorization state operation is unknown.');
