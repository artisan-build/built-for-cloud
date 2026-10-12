<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialVerbRefused;
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

const BFC_SIGNING_ROOT_AUTHORIZATION_WORKER = 'bfc-signing-root-authorization-worker';

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

/**
 * THE AUTHORIZED SUBJECT MUST BE THE MUTATED SUBJECT (security review
 * round 2).
 *
 * The exact target and the verb matrix answer different questions. The
 * target is what the CALLER claims the row is; the matrix is what the
 * DECLARATION permits for the row's own subject. Asking the matrix on the
 * unlocked pre-read and the target under the lock lets those two questions
 * land on different rows: the declaration is asked about the subject the
 * row used to have, while the lifecycle rotates the subject it has now.
 *
 * Here the declaration allows rotation for `app-a` and denies it for the
 * canonical signing-root subject, and the caller pins the canonical
 * identity it selected. The reserved row sits at `app-a` when the pre-read
 * happens and is canonical by the time the lifecycle lock is granted, so a
 * matrix consulted early says yes about a subject that is never mutated.
 */
it('refuses a signing-root rotation the declaration denies for the subject the locked row actually carries', function (): void {
    DB::table('bfc_authority')->updateOrInsert(
        ['key' => InstallationAuthority::KEY],
        [
            'mode' => AuthorityMode::Standalone->value,
            'generation' => 1,
            'created_at' => now(),
            'updated_at' => now(),
        ],
    );

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
        // The caller pins the CANONICAL identity — the one it selected
        // before the retarget — so the target check under the lock passes
        // and only the authority answer can refuse.
        'purpose' => CredentialPurpose::SigningRoot->value,
        'subject_type' => SubjectType::Installation->value,
        'subject_ref' => SigningRootMac::SUBJECT_REF,
        'kind' => CredentialKind::Hmac->value,
        'deny_subject_ref' => SigningRootMac::SUBJECT_REF,
        'application_name' => BFC_SIGNING_ROOT_AUTHORIZATION_WORKER,
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
                [BFC_SIGNING_ROOT_AUTHORIZATION_WORKER],
            );

            if ($waiting === 1) {
                $blocked = true;
                break;
            }
        }

        expect($blocked)->toBeTrue(
            'The rotation never waited on the installation authority lock, so this test cannot say which subject was authorized.',
        );

        $main->update('update credentials set subject_ref = ? where id = ?', [SigningRootMac::SUBJECT_REF, $root->id]);
        $main->commit();
        $worker->wait();

        expect($worker->isSuccessful())->toBeTrue($worker->getErrorOutput());

        $reported = json_decode($worker->getOutput(), true, flags: JSON_THROW_ON_ERROR);

        expect($reported['outcome'])->toBe(
            'refused',
            'The declaration was never asked about the canonical subject the lifecycle rotated.',
        )
            ->and($reported['refusal'])->toBe(CredentialVerbRefused::class)
            ->and(Credential::query()->where('purpose', CredentialPurpose::SigningRoot)->count())->toBe(1)
            ->and(Credential::query()->findOrFail($root->id)->rotated_at)->toBeNull();
    } finally {
        if ($worker->isRunning()) {
            $worker->stop();
        }

        if ($main->transactionLevel() > 0) {
            $main->rollBack();
        }
    }
})->note('Security review round 2. Revert the fix commit and the matrix is asked about app-a, which it allows, so a second root is created.');
