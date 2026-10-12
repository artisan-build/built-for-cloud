<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\Exceptions\RotationRefused;
use ArtisanBuild\BuiltForCloud\Hmac\HmacKeyring;
use ArtisanBuild\BuiltForCloud\Hmac\SigningRootMac;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Tests\Support\PostgresLane;
use Illuminate\Support\Facades\DB;
use Symfony\Component\Process\Process;

uses(PostgresLane::class)->group('pgsql');

const BFC_SIGNING_ROOT_TARGET_WORKER = 'bfc-signing-root-target-worker';

/**
 * THE SIGNING-ROOT LIFECYCLE LOCK (security review finding 2).
 *
 * A reserved row is reserved by its PURPOSE, so a signing-root row can carry
 * a subject ref that is not the canonical one. The lifecycle's own identity
 * check proves the CANONICAL identity and nothing about the identity a
 * caller pinned, so checking the caller's target on the unlocked pre-read
 * and trusting the lifecycle afterwards is not equivalent to checking it
 * under the lock: a noncanonical reserved row can BECOME canonical in
 * between, and the lifecycle then happily rotates it.
 *
 * This test holds the installation authority row the lifecycle locks, lets a
 * worker queue behind it, performs exactly that retarget, and commits. The
 * worker then reads the source under the lifecycle's own lock.
 */
it('refuses a signing-root rotation whose pinned identity changed before the lifecycle lock was granted', function (): void {
    DB::table('bfc_authority')->updateOrInsert(
        ['key' => InstallationAuthority::KEY],
        [
            'mode' => AuthorityMode::Standalone->value,
            'generation' => 1,
            'created_at' => now(),
            'updated_at' => now(),
        ],
    );

    // A reserved row that is reserved by its PURPOSE while carrying a
    // subject ref that is not the canonical one. The model refuses to
    // PERSIST that shape, so it is produced the way the package has to
    // assume a retarget happens: straight through the query builder. This
    // is the same framing the mint-path test uses — the package cannot
    // assume who moved a row or how.
    $encrypted = app(HmacKeyring::class)->encrypt(bin2hex(random_bytes(32)));
    $root = new Credential;
    $root->forceFill([
        'kind' => CredentialKind::Hmac,
        'purpose' => CredentialPurpose::SigningRoot,
        'subject_type' => SubjectType::Installation,
        'subject_ref' => SigningRootMac::SUBJECT_REF,
        'abilities' => null,
        'user_id' => null,
        'status' => CredentialStatus::Active,
        'secret_ciphertext' => $encrypted->ciphertext,
        'secret_key_version' => $encrypted->keyVersion,
    ])->save();
    DB::table('credentials')->where('id', $root->id)->update(['subject_ref' => 'app-a']);

    $main = $this->postgresLaneConnection();
    $main->beginTransaction();
    $main->select('select key from bfc_authority where key = ? for update', [InstallationAuthority::KEY]);

    $worker = new Process([PHP_BINARY, __DIR__.'/Fixtures/rotate-signing-root-target-worker.php']);
    $worker->setInput(json_encode([
        'credential_id' => $root->id,
        'purpose' => CredentialPurpose::SigningRoot->value,
        'subject_type' => SubjectType::Installation->value,
        'subject_ref' => 'app-a',
        'kind' => CredentialKind::Hmac->value,
        'application_name' => BFC_SIGNING_ROOT_TARGET_WORKER,
    ], JSON_THROW_ON_ERROR));

    try {
        $worker->start();
        $blocked = false;

        foreach (range(1, 5000) as $ignored) {
            if (! $worker->isRunning()) {
                throw new RuntimeException(
                    'The signing-root worker exited before it reached the installation lock: '
                    .$worker->getOutput().$worker->getErrorOutput(),
                );
            }

            $waiting = (int) $this->postgresLaneProbe()->scalar(
                <<<'SQL'
                    select count(*)
                    from pg_stat_activity
                    where datname = current_database()
                      and application_name = ?
                      and state = 'active'
                      and wait_event_type = 'Lock'
                      and query like '%bfc_authority%'
                    SQL,
                [BFC_SIGNING_ROOT_TARGET_WORKER],
            );

            if ($waiting === 1) {
                $blocked = true;
                break;
            }
        }

        expect($blocked)->toBeTrue(
            'The rotation never waited on the installation authority lock, so this test cannot say when the target was evaluated.',
        );

        // The retarget to the CANONICAL identity, committed with the lock
        // the worker is waiting for.
        $main->update('update credentials set subject_ref = ? where id = ?', [SigningRootMac::SUBJECT_REF, $root->id]);
        $main->commit();
        $worker->wait();

        expect($worker->isSuccessful())->toBeTrue($worker->getErrorOutput());

        $reported = json_decode($worker->getOutput(), true, flags: JSON_THROW_ON_ERROR);

        expect($reported['outcome'])->toBe(
            'refused',
            'The lifecycle rotated a root whose locked identity no longer matched the caller target.',
        )
            ->and($reported['refusal'])->toBe(RotationRefused::class)
            ->and($reported['message'])->toContain('subject')
            ->and(Credential::query()->where('purpose', CredentialPurpose::SigningRoot)->count())->toBe(1)
            ->and(Credential::query()->findOrFail($root->id)->rotated_at)->toBeNull()
            ->and(Credential::query()->findOrFail($root->id)->subject_ref)->toBe(SigningRootMac::SUBJECT_REF);
    } finally {
        if ($worker->isRunning()) {
            $worker->stop();
        }

        if ($main->transactionLevel() > 0) {
            $main->rollBack();
        }
    }
})->note('Security review finding 2. Revert the fix commit and the lifecycle creates a second root and stamps the old one instead of refusing.');
