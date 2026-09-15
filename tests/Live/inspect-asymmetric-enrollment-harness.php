<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AsymmetricVerificationKey;
use ArtisanBuild\BuiltForCloud\AsymmetricVerificationKeys;
use ArtisanBuild\BuiltForCloud\BoundCredentialScope;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use Illuminate\Contracts\Console\Kernel;

require __DIR__.'/../../vendor/autoload.php';

define('TESTBENCH_WORKING_PATH', dirname(__DIR__, 2));

$input = json_decode(stream_get_contents(STDIN), true, flags: JSON_THROW_ON_ERROR);
$app = require __DIR__.'/../../vendor/orchestra/testbench-core/laravel/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();
$scope = new BoundCredentialScope(
    'reel.application.signing',
    new Subject(SubjectType::Installation, 'reel-live-installation'),
    'install_live_1',
    'app_live_1',
    'https://reel-live.example',
);
$credential = Credential::query()->findOrFail((string) $input['credential_id']);
$token = OnboardingToken::query()->where('durable_credential_id', $credential->id)->sole();
$events = CredentialAuditEvent::query()->where('credential_id', $credential->id)->pluck('event')->all();

if ($input['mode'] === 'pending') {
    $passed = $credential->status === CredentialStatus::Pending
        && $credential->public_key === null
        && $token->consumed_at === null
        && $events === [LifecycleEventType::Issued];

    fwrite(STDOUT, json_encode(['pending_without_material' => $passed], JSON_THROW_ON_ERROR));
    exit($passed ? 0 : 1);
}

$keys = app(AsymmetricVerificationKeys::class)->for($scope);
$signature = base64_decode((string) $input['signature'], true);
$key = $keys[0] ?? null;
$verified = $key instanceof AsymmetricVerificationKey
    && is_string($signature)
    && openssl_verify((string) $input['payload'], $signature, $key->publicKey, OPENSSL_ALGO_SHA256) === 1;
$serialized = json_encode([
    $credential->getAttributes(),
    $token->getAttributes(),
    CredentialAuditEvent::query()->where('credential_id', $credential->id)->get()->toArray(),
], JSON_THROW_ON_ERROR);
$passed = $credential->status === CredentialStatus::Active
    && $token->consumed_at !== null
    && $events === [LifecycleEventType::Issued, LifecycleEventType::Exchanged, LifecycleEventType::Activated]
    && count($keys) === 1
    && $verified
    && ! str_contains($serialized, 'PRIVATE KEY');

fwrite(STDOUT, json_encode([
    'active' => $credential->status === CredentialStatus::Active,
    'code_consumed' => $token->consumed_at !== null,
    'transactional_audit' => $events === [LifecycleEventType::Issued, LifecycleEventType::Exchanged, LifecycleEventType::Activated],
    'lookup_returned_one_model_free_key' => count($keys) === 1 && $key instanceof AsymmetricVerificationKey,
    'retained_private_key_signature_verified' => $verified,
    'stored_private_marker_absent' => ! str_contains($serialized, 'PRIVATE KEY'),
], JSON_THROW_ON_ERROR));

exit($passed ? 0 : 1);
