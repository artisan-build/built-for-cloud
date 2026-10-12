<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\RotateCredential;
use ArtisanBuild\BuiltForCloud\Contracts\AuthorizesCredentialVerbs;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialOwnership;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\CredentialVerb;
use ArtisanBuild\BuiltForCloud\ExactCredentialTarget;
use ArtisanBuild\BuiltForCloud\Exceptions\RotationCutoverIncomplete;
use ArtisanBuild\BuiltForCloud\Exceptions\RotationRefused;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\RotateOptions;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Tests\Support\PostgresLane;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Symfony\Component\Process\Process;

uses(PostgresLane::class)->group('pgsql');

const BFC_RETARGET_WORKER_NAME = 'bfc-cutover-retarget-worker';

/**
 * THE PHASE-TWO WINDOW (security review finding 1).
 *
 * Phase one proves the exact target under the source row lock and then
 * COMMITS, which releases that lock — deliberately, because phase two is a
 * separate, separately fallible write and the contract says no caller wraps
 * rotation in an outer transaction. But phase two MUTATES the source: it
 * shortens the expiry to the grace end. A retarget that queues behind phase
 * one's lock commits the instant phase one does, and the retirement then
 * lands on a row that has moved to another subject.
 *
 * The interleave has to put the retarget INSIDE that window, which means
 * starting it while phase one holds the lock. The hook is the package's own
 * verb matrix: `authorizeVerb()` is consulted inside `mintReplacement`,
 * after `lockForUpdate()` has returned. From there this test starts the
 * retargeting process and waits until Postgres reports it blocked on a lock
 * over `credentials`. Lock grants are FIFO, so the retarget is served before
 * phase two's own lock request and the ordering needs no sleeps.
 */
function cutoverRetargetDeclaration(callable $onRotateAuthorized): void
{
    app()->instance(CredentialDeclaration::class, new class($onRotateAuthorized) implements AuthorizesCredentialVerbs, CredentialDeclaration
    {
        private bool $fired = false;

        /** @param callable(): void $onRotateAuthorized */
        public function __construct(private $onRotateAuthorized) {}

        public function resolveSubject(Request $request): ?Subject
        {
            return null;
        }

        public function authorize(Credential $credential, ?string $ability, Request $request): bool
        {
            return true;
        }

        public function authorizeVerb(CredentialVerb $verb, ?Subject $subject, Request $request): bool
        {
            if ($verb === CredentialVerb::Rotate && ! $this->fired) {
                $this->fired = true;
                ($this->onRotateAuthorized)();
            }

            return true;
        }
    });
}

it('refuses the cutover retirement when the source is retargeted between phase one and phase two', function (): void {
    // A rotated app-a bearer credential with a live successor and an expiry
    // 30 days out: the shape a cutover completion is for.
    $successor = Credential::factory()->create([
        'kind' => CredentialKind::Bearer,
        'purpose' => CredentialPurpose::Consumption,
        'subject_type' => SubjectType::Installation,
        'subject_ref' => 'app-a',
        'name' => 'ingest',
        'user_id' => null,
        'status' => CredentialStatus::Active,
        'expires_at' => now()->addDays(30),
    ]);
    $source = Credential::factory()->create([
        'kind' => CredentialKind::Bearer,
        'purpose' => CredentialPurpose::Consumption,
        'subject_type' => SubjectType::Installation,
        'subject_ref' => 'app-a',
        'name' => 'ingest',
        'user_id' => null,
        'status' => CredentialStatus::Active,
        'rotated_at' => now()->subMinutes(5),
        'expires_at' => now()->addDays(30),
    ]);
    CredentialAuditEvent::query()->create([
        'id' => (string) Str::uuid(),
        'event' => LifecycleEventType::Rotated,
        'credential_id' => $source->id,
        'superseded_by_credential_id' => $successor->id,
        'environment' => app()->environment(),
        'occurred_at' => now()->subMinutes(5),
    ]);
    $sourceExpiry = Credential::query()->findOrFail($source->id)->expires_at;

    $target = new ExactCredentialTarget(
        purpose: CredentialPurpose::Consumption,
        subject: new Subject(SubjectType::Installation, 'app-a'),
        kind: CredentialKind::Bearer,
        ownership: CredentialOwnership::Installation,
    );

    $retargeter = new Process([PHP_BINARY, __DIR__.'/Fixtures/retarget-credential-worker.php']);
    $retargeter->setInput(json_encode([
        'id' => $source->id,
        'column' => 'subject_ref',
        'value' => 'app-b',
        'application_name' => BFC_RETARGET_WORKER_NAME,
    ], JSON_THROW_ON_ERROR));

    cutoverRetargetDeclaration(function () use ($retargeter): void {
        // Inside phase one, with the source row locked.
        $retargeter->start();

        foreach (range(1, 5000) as $ignored) {
            if (! $retargeter->isRunning()) {
                throw new RuntimeException(
                    'The retargeting process finished without ever queueing behind phase one: '
                    .$retargeter->getOutput().$retargeter->getErrorOutput(),
                );
            }

            $blocked = (int) DB::connection('pgsql_testing_probe')->scalar(
                <<<'SQL'
                    select count(*)
                    from pg_stat_activity
                    where datname = current_database()
                      and application_name = ?
                      and state = 'active'
                      and wait_event_type = 'Lock'
                      and query like '%credentials%'
                    SQL,
                [BFC_RETARGET_WORKER_NAME],
            );

            if ($blocked === 1) {
                return;
            }
        }

        throw new RuntimeException('The retargeting process never blocked on the phase-one source lock.');
    });

    $failure = null;

    try {
        app(RotateCredential::class)($source->id, new RotateOptions(target: $target));
    } catch (Throwable $exception) {
        $failure = $exception;
    } finally {
        if ($retargeter->isRunning()) {
            $retargeter->wait();
        }
    }

    expect($retargeter->isSuccessful())->toBeTrue($retargeter->getErrorOutput());

    $reported = json_decode($retargeter->getOutput(), true, flags: JSON_THROW_ON_ERROR);
    $retired = Credential::query()->findOrFail($source->id);

    expect($reported['rows'])->toBe(1)
        ->and($retired->subject_ref)->toBe('app-b')
        // THE REGRESSION. Before the fix, phase two updated by id alone and
        // shortened a row that had moved to app-b to the one-hour grace end.
        ->and($retired->expires_at?->toDateTimeString())->toBe(
            $sourceExpiry?->toDateTimeString(),
            'Phase two retired a credential that had been retargeted to another subject.',
        )
        ->and($retired->expires_at?->isAfter(now()->addDays(29)))->toBeTrue()
        ->and($failure)->toBeInstanceOf(RotationCutoverIncomplete::class)
        ->and($failure?->getPrevious())->toBeInstanceOf(RotationRefused::class)
        ->and($failure?->getMessage())->toContain('was NOT retired')
        // Phase one still stands, which is the contract and is what the
        // refusal reports rather than hides.
        ->and(CredentialAuditEvent::query()
            ->where('credential_id', $source->id)
            ->where('event', LifecycleEventType::Rotated->value)
            ->count())->toBe(2)
        ->and(Credential::query()->count())->toBe(2);
})->note('Security review finding 1. Revert the fix commit and phase two shortens the app-b row to the grace end instead of refusing.');
