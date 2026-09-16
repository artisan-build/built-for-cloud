<?php

declare(strict_types=1);

use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\RateLimiter;
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

if ($input['operation'] === 'clear-token-limiters') {
    foreach (['bfc-device-token|127.0.0.1', 'bfc-loopback-token|127.0.0.1', 'bfc-authorization-token-global'] as $key) {
        RateLimiter::clear(md5('bfc-authorization-token'.$key));
    }

    fwrite(STDOUT, "{\"cleared\":true}\n");

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
