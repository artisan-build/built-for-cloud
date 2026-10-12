<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\Exceptions\RotationRefused;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Tests\Support\PostgresLane;
use Symfony\Component\Process\Process;

uses(PostgresLane::class)->group('pgsql');

/**
 * THE LOCKED-BOUNDARY CLAIM, on the driver that implements row locks.
 *
 * A consumer pre-selects a credential by purpose and subject and then calls
 * rotation by id. The window this test is about is the one between that
 * selection and the rotation's own write: if the row is RETARGETED inside
 * it, an id-only rotation operates on something the caller never selected.
 *
 * The predicate therefore has to be re-proved against the row the rotation
 * has LOCKED — not against the row the caller read, and not against the
 * unlocked read the verb itself takes on the way in. Only a second process
 * can tell those apart, so one rotates while this test holds the row:
 *
 *   1. the worker starts, takes its unlocked reads (the row still reads
 *      `app-a`, so a pre-lock check would PASS), and blocks on
 *      `lockForUpdate()`;
 *   2. `pg_stat_activity` confirms it is blocked on a lock over
 *      `credentials` — the deterministic observation, no sleeps;
 *   3. this test retargets the row to `app-b` and commits, which is the
 *      concurrent retarget;
 *   4. the worker's lock acquires, the predicate is re-evaluated on what
 *      the lock returned, and the rotation refuses.
 *
 * Move the check to the verb's unlocked read and step 4 mints a
 * replacement for an app that never asked for one.
 */
it('refuses a rotation whose exact target was retargeted while the rotation waited for the row lock', function (): void {
    $source = Credential::factory()->create([
        'kind' => CredentialKind::Bearer,
        'purpose' => CredentialPurpose::Consumption,
        'subject_type' => SubjectType::Installation,
        'subject_ref' => 'app-a',
        'name' => 'ingest',
        'user_id' => null,
        'expires_at' => now()->addDays(30),
    ]);

    $main = $this->postgresLaneConnection();
    $main->beginTransaction();
    $main->select('select id from credentials where id = ? for update', [$source->id]);

    $worker = new Process([PHP_BINARY, __DIR__.'/Fixtures/rotate-exact-target-worker.php']);
    $worker->setInput(json_encode([
        'credential_id' => $source->id,
        'purpose' => CredentialPurpose::Consumption->value,
        'subject_type' => SubjectType::Installation->value,
        'subject_ref' => 'app-a',
        'kind' => CredentialKind::Bearer->value,
    ], JSON_THROW_ON_ERROR));

    try {
        $worker->start();
        $blocked = false;

        foreach (range(1, 5000) as $ignored) {
            if (! $worker->isRunning()) {
                throw new RuntimeException(
                    'The rotating worker exited before it blocked on the credential row lock: '
                    .$worker->getOutput().$worker->getErrorOutput(),
                );
            }

            $waiting = (int) $this->postgresLaneProbe()->scalar(<<<'SQL'
                select count(*)
                from pg_stat_activity
                where datname = current_database()
                  and application_name = 'bfc-rotate-exact-target-worker'
                  and state = 'active'
                  and wait_event_type = 'Lock'
                  and query like '%credentials%'
                SQL);

            if ($waiting === 1) {
                $blocked = true;
                break;
            }
        }

        expect($blocked)->toBeTrue(
            'The rotation never waited on the source row lock, so this test cannot say when the predicate was evaluated.',
        );

        // The concurrent retarget, committed while the rotation is parked
        // on the lock it is about to be handed.
        $main->update('update credentials set subject_ref = ? where id = ?', ['app-b', $source->id]);
        $main->commit();
        $worker->wait();

        expect($worker->isSuccessful())->toBeTrue($worker->getErrorOutput());

        $reported = json_decode($worker->getOutput(), true, flags: JSON_THROW_ON_ERROR);

        expect($reported['outcome'])->toBe(
            'refused',
            'The rotation completed on the retargeted row: the predicate was not re-evaluated under the lock.',
        )
            ->and($reported['refusal'])->toBe(RotationRefused::class)
            ->and($reported['message'])->toContain('subject')
            ->and(Credential::query()->count())->toBe(1)
            ->and(Credential::query()->findOrFail($source->id)->rotated_at)->toBeNull()
            ->and(Credential::query()->findOrFail($source->id)->subject_ref)->toBe('app-b')
            ->and(CredentialAuditEvent::query()->count())->toBe(0);
    } finally {
        if ($worker->isRunning()) {
            $worker->stop();
        }

        if ($main->transactionLevel() > 0) {
            $main->rollBack();
        }
    }
})->note('AC2. Mutation: move `$options->target?->assertMatches(...)` out of RotateCredential::mintReplacement and onto the unlocked read in __invoke. The worker then rotates the retargeted row instead of refusing.');
