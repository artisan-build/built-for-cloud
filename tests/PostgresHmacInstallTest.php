<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\BoundCredentialScope;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialOutboxEntry;
use ArtisanBuild\BuiltForCloud\CredentialProtocolBinding;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\Tests\Support\PostgresLane;
use Illuminate\Support\Str;
use Symfony\Component\Process\Process;

uses(PostgresLane::class)->group('pgsql');

it('serializes concurrent receiver installers into one write and one exact idempotent result', function (): void {
    testsConfigureBoundPurposes();
    $scope = testsBoundScope('matte.callback');
    $oldKey = str_repeat('a', 64);
    $newKey = str_repeat('b', 64);
    $encrypted = app(HmacKeyring::class)->encrypt($oldKey);
    $predecessor = Credential::factory()->hmac()->activated()->create([
        'subject_type' => $scope->subject->type,
        'subject_ref' => $scope->subject->ref,
        'secret_ciphertext' => $encrypted->ciphertext,
        'secret_key_version' => $encrypted->keyVersion,
        'delivered_generation' => 1,
        'delivery_fingerprint' => app(HmacKeyring::class)->deliveryFingerprint($oldKey, 1),
    ]);
    CredentialProtocolBinding::createVerificationCopy($predecessor, $scope);
    $replacementId = (string) Str::uuid();
    $deliveredAt = now()->toImmutable();
    $input = [
        'replacement_id' => $replacementId,
        'predecessor_id' => $predecessor->id,
        'app_purpose' => $scope->appPurpose,
        'subject_type' => $scope->subject->type->value,
        'subject_ref' => $scope->subject->ref,
        'installation' => $scope->installation,
        'application' => $scope->application,
        'audience' => $scope->audience,
        'credential_expires_at' => now()->addDay()->toRfc3339String(),
        'generation' => 2,
        'fingerprint' => app(HmacKeyring::class)->deliveryFingerprint($newKey, 2),
        'delivered_at' => $deliveredAt->toRfc3339String(),
        'transfer_expires_at' => $deliveredAt->addSeconds(60)->toRfc3339String(),
        'key' => $newKey,
    ];
    $main = $this->postgresLaneConnection();
    $main->beginTransaction();
    $main->table('credentials')->where('id', $predecessor->id)->lockForUpdate()->sole();
    $workers = [];

    try {
        foreach ([1, 2] as $workerId) {
            $worker = new Process([PHP_BINARY, __DIR__.'/Fixtures/hmac-install-worker.php']);
            $worker->setInput(json_encode($input + ['worker' => $workerId], JSON_THROW_ON_ERROR));
            $worker->start();
            $workers[] = $worker;
        }

        foreach (range(1, 5000) as $ignored) {
            foreach ($workers as $worker) {
                if (! $worker->isRunning()) {
                    throw new RuntimeException('A HMAC install worker exited before lock release: '.$worker->getOutput().$worker->getErrorOutput());
                }
            }

            $blocked = (int) $this->postgresLaneProbe()->scalar(<<<'SQL'
                select count(*) from pg_stat_activity
                where datname = current_database()
                  and application_name like 'bfc-hmac-install-worker-%'
                  and state = 'active'
                  and wait_event_type = 'Lock'
                  and query like '%credentials%'
                SQL);

            if ($blocked === 2) {
                break;
            }
        }

        expect($blocked ?? 0)->toBe(2);
        $main->commit();
        $results = [];

        foreach ($workers as $worker) {
            $worker->wait();
            expect($worker->isSuccessful())->toBeTrue($worker->getErrorOutput());
            $results[] = json_decode($worker->getOutput(), true, flags: JSON_THROW_ON_ERROR);
        }

        expect(array_column($results, 'outcome'))->toBe(['installed', 'installed'])
            ->and(array_unique(array_column($results, 'credential_id')))->toBe([$replacementId])
            ->and(Credential::query()->whereKey($replacementId)->count())->toBe(1)
            ->and(CredentialAuditEvent::query()->where('credential_id', $replacementId)->count())->toBe(3)
            ->and(CredentialAuditEvent::query()->where('credential_id', $predecessor->id)->where('event', LifecycleEventType::Rotated)->count())->toBe(1)
            ->and(CredentialOutboxEntry::query()->count())->toBe(4);
    } finally {
        foreach ($workers as $worker) {
            if ($worker->isRunning()) {
                $worker->stop();
            }
        }

        if ($main->transactionLevel() > 0) {
            $main->rollBack();
        }
    }
});
