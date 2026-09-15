<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialOutboxEntry;
use ArtisanBuild\BuiltForCloud\Hmac\HmacEnvelope;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

require __DIR__.'/../../vendor/autoload.php';

define('TESTBENCH_WORKING_PATH', dirname(__DIR__, 2));
$input = json_decode(stream_get_contents(STDIN), true, flags: JSON_THROW_ON_ERROR);
$app = require __DIR__.'/../../vendor/orchestra/testbench-core/laravel/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();

if (($input['mode'] ?? null) === 'initialize') {
    if (! Schema::hasTable('bfc_hmac_harness_dispatches')) {
        Schema::create('bfc_hmac_harness_dispatches', function (Blueprint $table): void {
            $table->id();
            $table->uuid('credential_id');
            $table->string('body_hash', 64);
        });
    }

    fwrite(STDOUT, json_encode(['initialized' => true], JSON_THROW_ON_ERROR));
    exit(0);
}

$credentialId = (string) ($input['credential_id'] ?? '');
$credential = Credential::query()->findOrFail($credentialId);

if (($input['mode'] ?? null) === 'mutate') {
    $changes = match ($input['mutation'] ?? null) {
        'revoke' => ['revoked_at' => now()],
        'expire' => ['expires_at' => now()->subSecond()],
        'poison-key-version' => ['secret_key_version' => 'must-not-decrypt'],
        default => throw new RuntimeException('Unknown HMAC harness mutation.'),
    };
    Credential::query()->whereKey($credentialId)->update($changes);
    fwrite(STDOUT, json_encode(['mutated' => true], JSON_THROW_ON_ERROR));
    exit(0);
}

$header = $input['header'] ?? null;
$ratePresent = false;
$noncePresent = false;

if (is_string($header)) {
    [$envelope] = HmacEnvelope::parse($header);
    $ratePresent = Cache::has('bfc:hmac:rate:'.$envelope->keyId);
    $noncePresent = Cache::has('bfc:hmac:nonce:'.hash('sha256', $envelope->keyId.'|'.$envelope->nonce));
}

$serialized = json_encode([
    $credential->getAttributes(),
    CredentialAuditEvent::query()->get()->toArray(),
    CredentialOutboxEntry::query()->get()->toArray(),
], JSON_THROW_ON_ERROR);
$canary = getenv('BFC_HARNESS_HMAC_CANARY');

fwrite(STDOUT, json_encode([
    'ciphertext_present' => is_string($credential->secret_ciphertext) && $credential->secret_ciphertext !== '',
    'plaintext_hash_absent' => $credential->secret_hash === null,
    'canary_absent_from_persistence' => ! is_string($canary) || ! str_contains($serialized, $canary),
    'audit_events' => CredentialAuditEvent::query()->where('credential_id', $credentialId)->count(),
    'outbox_entries' => CredentialOutboxEntry::query()->count(),
    'dispatches' => DB::table('bfc_hmac_harness_dispatches')->count(),
    'last_used' => $credential->last_used_at !== null,
    'rate_present' => $ratePresent,
    'nonce_present' => $noncePresent,
], JSON_THROW_ON_ERROR));
