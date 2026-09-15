<?php

declare(strict_types=1);

use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\RateLimiter;

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

throw new RuntimeException('The device authorization state operation is unknown.');
