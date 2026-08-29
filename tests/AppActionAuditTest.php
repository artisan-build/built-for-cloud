<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Audit\AppActionActor;
use ArtisanBuild\BuiltForCloud\Audit\AppActionEvent;
use ArtisanBuild\BuiltForCloud\Audit\AppActionOutboxEntry;
use ArtisanBuild\BuiltForCloud\Audit\AppActionReason;
use ArtisanBuild\BuiltForCloud\Audit\AppActionRecorder;
use ArtisanBuild\BuiltForCloud\Audit\AppActorType;
use ArtisanBuild\BuiltForCloud\AuditActorType;
use ArtisanBuild\BuiltForCloud\Console\ActingPrincipalResolver;
use ArtisanBuild\BuiltForCloud\Console\ConsoleGuardConfiguration;
use ArtisanBuild\BuiltForCloud\Console\DelegatedActor;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialOutboxEntry;
use ArtisanBuild\BuiltForCloud\Tests\AppActionRetentionScan;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\CountedAppAction;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\SinkAppAction;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\UnboundedAppAction;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\User;
use Illuminate\Database\QueryException;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;

uses(RefreshDatabase::class);

/**
 * The app-action audit stream (Console PRD D17): a NEW append-only
 * stream, its own table, its own outbox, its own emission point — and
 * the credential stream untouched.
 */

/**
 * The exact columns the CREDENTIAL audit stream had before this PR, in
 * the order its migration declares them. Spelled out rather than
 * compared to a snapshot, because the property being pinned is that this
 * PR added nothing to it and the enumeration is the only shape that can
 * say so.
 *
 * @return list<string>
 */
function shippedCredentialAuditColumns(): array
{
    return [
        'id', 'event', 'code_id', 'credential_id', 'superseded_by_credential_id',
        'provider', 'deployment', 'environment', 'actor_type', 'actor_ref',
        'recipient', 'code_ttl_seconds', 'credential_expires_at', 'reason_code',
        'note', 'occurred_at', 'created_at',
    ];
}

/**
 * Record one app action inside a transaction, through the real recorder.
 */
function recordAppAction(
    ?AppActionActor $actor = null,
    ?string $dedupKey = null,
    AppActionReason $reason = AppActionReason::Requested,
): AppActionEvent {
    $actor ??= AppActionActor::delegated(consoleActor(), 'Acme Agency');

    return DB::transaction(fn (): AppActionEvent => app(AppActionRecorder::class)->record(
        action: SinkAppAction::InvoiceVoided,
        actor: $actor,
        reason: $reason,
        dedupKey: $dedupKey,
    ));
}

// ─── AC1: a NEW stream, not an extension ────────────────────────────────────

it('leaves the credential stream\'s shape untouched', function (): void {
    // The credential stream is credential-work only and D17 does not
    // extend it. An added column here would be this PR quietly widening
    // a shipped record instead of opening its own.
    expect(Schema::getColumnListing('credential_audit_events'))->toBe(shippedCredentialAuditColumns());

    // And the new stream is genuinely a different table.
    expect(Schema::hasTable('bfc_app_action_events'))->toBeTrue()
        ->and(Schema::hasTable('bfc_app_action_outbox'))->toBeTrue();
});

it('writes nothing to the credential stream when an app action is recorded', function (): void {
    recordAppAction();

    expect(AppActionEvent::query()->count())->toBe(1)
        ->and(CredentialAuditEvent::query()->count())->toBe(0)
        ->and(CredentialOutboxEntry::query()->count())->toBe(0);
});

// ─── AC2: append-only, with the shipped enforcement shape ───────────────────

it('rejects update and delete on an app-action event at the model layer', function (): void {
    $row = recordAppAction();

    expect(fn (): bool => $row->update(['action' => 'rewritten-history']))
        ->toThrow(LogicException::class, 'append-only');

    expect(fn (): ?bool => $row->delete())
        ->toThrow(LogicException::class, 'append-only');

    expect(AppActionEvent::query()->findOrFail($row->id)->action)->toBe(SinkAppAction::InvoiceVoided->value);
});

it('rejects truncate on the app-action stream, on both the static and the query-builder paths', function (): void {
    // TRUNCATE is DDL on mysql, where the row triggers never fire — the
    // model layer must refuse it before the driver sees it. Raw
    // `DB::table(...)->truncate()` and raw TRUNCATE SQL bypass the model
    // and are outside the package's enforcement boundary: a
    // database-privilege matter, exactly as the model docblock says.
    $row = recordAppAction();

    expect(fn (): mixed => AppActionEvent::truncate())
        ->toThrow(LogicException::class, 'never truncated');

    expect(fn (): mixed => AppActionEvent::query()->truncate())
        ->toThrow(LogicException::class, 'never truncated');

    expect(AppActionEvent::query()->whereKey($row->id)->exists())->toBeTrue();
});

it('rejects raw update and delete on the app-action table at the database layer on sqlite', function (): void {
    // Model guards do not see raw writes; the triggers do.
    $row = recordAppAction();

    expect(fn (): int => DB::table('bfc_app_action_events')->where('id', $row->id)->update(['action' => 'tampered']))
        ->toThrow(QueryException::class, 'append-only');

    expect(fn (): int => DB::table('bfc_app_action_events')->where('id', $row->id)->delete())
        ->toThrow(QueryException::class, 'append-only');

    expect(AppActionEvent::query()->findOrFail($row->id)->action)->toBe(SinkAppAction::InvoiceVoided->value);
})->skip(fn (): bool => DB::connection()->getDriverName() !== 'sqlite', 'database-layer enforcement is per-driver; this suite runs sqlite');

// ─── AC3: a stable, package-generated event id ──────────────────────────────

it('stamps every app-action event with a package-generated uuid', function (): void {
    $first = recordAppAction();
    $second = recordAppAction();

    expect($first->id)->toMatch('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/')
        ->and($second->id)->not->toBe($first->id)
        // Read back from storage, not from the in-memory model: the id
        // is on the ROW, not merely on the object that made it.
        ->and(AppActionEvent::query()->pluck('id')->sort()->values()->all())
        ->toBe(collect([$first->id, $second->id])->sort()->values()->all());
});

// ─── AC4: two vocabularies, disjoint ────────────────────────────────────────

it('keeps the two audit vocabularies disjoint, so neither stream can hand a reader the other\'s actor type', function (): void {
    $appActionTypes = array_map(fn (AppActorType $type): string => $type->value, AppActorType::cases());
    $credentialTypes = array_map(fn (AuditActorType $type): string => $type->value, AuditActorType::cases());

    // The three principals D17 names, and nothing else.
    expect($appActionTypes)->toBe(['local_user', 'api_token', 'delegated_actor']);

    // Neither vocabulary contains a member of the other. A reader of
    // either stream can therefore enumerate what it may be handed
    // without first asking which stream the row came from.
    expect(array_intersect($appActionTypes, $credentialTypes))->toBe([]);

    // The specific direction that would have been wrong: the credential
    // stream must never gain a delegated actor.
    expect($credentialTypes)->not->toContain(AppActorType::DelegatedActor->value);
});

// ─── AC5: on_behalf_of, in all three directions ─────────────────────────────

it('carries the agency a delegated handoff named', function (): void {
    $event = recordAppAction(AppActionActor::delegated(consoleActor(), 'Acme Agency'));

    expect(AppActionEvent::query()->findOrFail($event->id)->on_behalf_of)->toBe('Acme Agency');
});

it('records a delegated event with no agency as null rather than inventing one', function (): void {
    // The issuer is NOT substituted, and neither is the display name:
    // absence is recorded as absence.
    $event = recordAppAction(AppActionActor::delegated(consoleActor(onBehalfOf: null), null));

    expect(AppActionEvent::query()->findOrFail($event->id)->on_behalf_of)->toBeNull();
});

it('cannot construct a local user or api token actor that carries an agency at all', function (): void {
    $user = User::query()->create(['name' => 'Local', 'email' => 'local@example.test', 'password' => 'x']);

    $event = recordAppAction(AppActionActor::localUser($user));

    $stored = AppActionEvent::query()->findOrFail($event->id);

    expect($stored->actor_type)->toBe(AppActorType::LocalUser)
        ->and($stored->actor_ref)->toBe((string) $user->getKey())
        ->and($stored->on_behalf_of)->toBeNull();

    // …and it is structural, not merely unset: the two non-delegated
    // named constructors have no parameter to put an agency in, and the
    // constructor that does is private.
    expect((new ReflectionMethod(AppActionActor::class, 'localUser'))->getNumberOfParameters())->toBe(1)
        ->and((new ReflectionMethod(AppActionActor::class, 'apiToken'))->getNumberOfParameters())->toBe(1)
        ->and((new ReflectionMethod(AppActionActor::class, '__construct'))->isPrivate())->toBeTrue();
});

// ─── AC6: the delegated actor is type-qualified ─────────────────────────────

it('names a delegated actor by its type-qualified identity, where a user with the same numeric id also exists', function (): void {
    $user = User::query()->create(['name' => 'Local', 'email' => 'local@example.test', 'password' => 'x']);
    $actor = consoleActor();

    // The fixture the claim is about: both id spaces occupied at the
    // same number, which is the routine case rather than a contrived one.
    expect($actor->getKey())->toBe($user->getKey());

    $event = recordAppAction(AppActionActor::delegated($actor, null));

    $stored = AppActionEvent::query()->findOrFail($event->id);

    expect($stored->actor_ref)->toBe(DelegatedActor::IDENTIFIER_PREFIX.$actor->getKey())
        ->and($stored->actor_ref)->not->toBe((string) $user->getKey())
        ->and($stored->actor_type)->toBe(AppActorType::DelegatedActor);
});

// ─── AC7: attribution comes from the ONE acting principal (D14) ─────────────

it('attributes to the acting principal and not to the delegated session co-resident on the same request', function (): void {
    // The route is guarded by the APP's own guard while a delegated
    // session is also live, so the two sources genuinely disagree: the
    // acting principal is the local user, and asking the console guard
    // directly would have named the delegated actor. The event must name
    // the first.
    Route::middleware([StartSession::class])->get('/app-action-probe', function (): array {
        $acting = app(ActingPrincipalResolver::class)->resolve();

        $event = DB::transaction(fn (): AppActionEvent => app(AppActionRecorder::class)->record(
            action: SinkAppAction::TeammateInvited,
            actor: AppActionActor::fromActingPrincipal($acting),
            reason: AppActionReason::Requested,
        ));

        return [
            'event' => $event->id,
            // What the SECOND source would have said, observed on the
            // same request rather than argued about.
            'console_guard_says' => Auth::guard(ConsoleGuardConfiguration::GUARD)->id(),
        ];
    });

    $user = User::query()->create(['name' => 'Local', 'email' => 'local@example.test', 'password' => 'x']);
    $actor = consoleActor(displayName: 'Jane Operator', onBehalfOf: 'Acme Agency');

    $response = $this->actingAs($user)->withSession(consoleSessionState($actor))
        ->getJson('/app-action-probe')
        ->assertOk();

    // The delegated session really was live on this request…
    expect($response->json('console_guard_says'))
        ->toBe(DelegatedActor::IDENTIFIER_PREFIX.$actor->getKey());

    // …and the event names the acting principal, with no agency, because
    // a local user acts for nobody.
    $stored = AppActionEvent::query()->findOrFail($response->json('event'));

    expect($stored->actor_type)->toBe(AppActorType::LocalUser)
        ->and($stored->actor_ref)->toBe((string) $user->getKey())
        ->and($stored->on_behalf_of)->toBeNull();
});

it('refuses an app action nobody is acting for', function (): void {
    // An unattributed app action is not a weaker record; it is a row
    // asserting less than the stream promises. The emission is refused.
    Route::middleware([StartSession::class])->get('/app-action-anon', function (): array {
        DB::transaction(fn (): AppActionEvent => app(AppActionRecorder::class)->record(
            action: SinkAppAction::TeammateInvited,
            actor: AppActionActor::fromActingPrincipal(app(ActingPrincipalResolver::class)->resolve()),
            reason: AppActionReason::Requested,
        ));

        return ['ok' => true];
    });

    $this->withoutExceptionHandling();

    expect(fn (): mixed => $this->getJson('/app-action-anon'))
        ->toThrow(LogicException::class, 'no unattributed app action');

    expect(AppActionEvent::query()->count())->toBe(0);
});

// ─── AC8: the action is an enum case, and the refusal actually fires ────────

it('refuses an action whose case is backed by prose rather than a bounded identifier', function (): void {
    // THE POSITIVE CONTROL. An enum type stops runtime data; it does not
    // stop an app writing a sentence into a case, and an instrument
    // nobody has watched fail is an unproven claim.
    expect(fn (): mixed => DB::transaction(fn (): AppActionEvent => app(AppActionRecorder::class)->record(
        action: UnboundedAppAction::Whatever,
        actor: AppActionActor::delegated(consoleActor(), null),
        reason: AppActionReason::Requested,
    )))->toThrow(LogicException::class, 'bounded identifier');

    // …and nothing was stored: the refusal is total, not a trim.
    expect(AppActionEvent::query()->count())->toBe(0)
        ->and(AppActionOutboxEntry::query()->count())->toBe(0);
});

it('refuses an action backed by an integer rather than an identifier', function (): void {
    expect(fn (): mixed => DB::transaction(fn (): AppActionEvent => app(AppActionRecorder::class)->record(
        action: CountedAppAction::Something,
        actor: AppActionActor::delegated(consoleActor(), null),
        reason: AppActionReason::Requested,
    )))->toThrow(LogicException::class, 'bounded identifier');

    expect(AppActionEvent::query()->count())->toBe(0);
});

it('cannot be handed a free-text action at all, because the parameter is typed', function (): void {
    // The `list<string>` vocabulary this replaced would have accepted
    // `Tag::pluck('slug')`. The parameter is an AppAction — a BackedEnum
    // — so a string does not reach the body of the method: PHP refuses
    // the call. Driven rather than asserted about the signature, because
    // the signature is what a reader would have to trust otherwise.
    expect(fn (): mixed => DB::transaction(fn (): AppActionEvent => app(AppActionRecorder::class)->record(
        action: 'invoice-voided',
        actor: AppActionActor::delegated(consoleActor(), null),
        reason: AppActionReason::Requested,
    )))->toThrow(TypeError::class);

    expect(AppActionEvent::query()->count())->toBe(0);

    // And the well-formed case that a passing vocabulary produces, so
    // this test cannot pass by refusing everything.
    $event = recordAppAction();

    expect(AppActionEvent::query()->findOrFail($event->id)->action)->toBe('invoice-voided');
});

it('records which vocabulary the action name came from', function (): void {
    // Two apps may both declare `invoice-voided` and mean different
    // things; a bare slug leaves a reader unable to tell. The class is a
    // compile-time constant, not runtime data.
    $event = recordAppAction();

    expect(AppActionEvent::query()->findOrFail($event->id)->action_vocabulary)->toBe(SinkAppAction::class);
});

// ─── AC10: transactionality ─────────────────────────────────────────────────

it('writes the event and its outbox row in the caller\'s own transaction', function (): void {
    $event = recordAppAction(dedupKey: 'invoice-42-voided');

    $outbox = AppActionOutboxEntry::query()->sole();

    expect($outbox->event_id)->toBe($event->id)
        ->and($outbox->dedup_key)->toBe('invoice-42-voided');
});

it('leaves neither the event nor its outbox row behind when the action rolls back', function (): void {
    // Driven by an ACTUAL rollback: the action fails after its event was
    // appended, and the record goes with it. A stream that survived its
    // own action's rollback would record things that did not happen.
    expect(fn (): mixed => DB::transaction(function (): void {
        app(AppActionRecorder::class)->record(
            action: SinkAppAction::InvoiceVoided,
            actor: AppActionActor::delegated(consoleActor(), null),
            reason: AppActionReason::Requested,
        );

        throw new RuntimeException('the action itself failed');
    }))->toThrow(RuntimeException::class, 'the action itself failed');

    expect(AppActionEvent::query()->count())->toBe(0)
        ->and(AppActionOutboxEntry::query()->count())->toBe(0);
});

// ─── AC11: exactly one event per action ─────────────────────────────────────

it('refuses a second emission of the same logical action, and takes the transaction with it', function (): void {
    $failed = false;

    try {
        DB::transaction(function (): void {
            foreach ([1, 2] as $ignored) {
                app(AppActionRecorder::class)->record(
                    action: SinkAppAction::InvoiceVoided,
                    actor: AppActionActor::delegated(consoleActor(), null),
                    reason: AppActionReason::Requested,
                    dedupKey: 'invoice-42-voided',
                );
            }
        });
    } catch (UniqueConstraintViolationException) {
        $failed = true;
    }

    // The duplicate did not merely fail to insert: it took the whole
    // transaction, the FIRST event included. That is the intended shape —
    // the same logical action is never recorded twice, and a caller that
    // tried is told rather than left with one of two.
    expect($failed)->toBeTrue()
        ->and(AppActionEvent::query()->count())->toBe(0)
        ->and(AppActionOutboxEntry::query()->count())->toBe(0);

    // Two DIFFERENT logical actions are of course both recorded.
    recordAppAction(dedupKey: 'invoice-42-voided');
    recordAppAction(dedupKey: 'invoice-43-voided');

    expect(AppActionEvent::query()->count())->toBe(2);
});

// ─── AC15: declared retention — nothing prunes this stream ──────────────────

it('ships no pruning path for the app-action stream anywhere in src', function (): void {
    $root = dirname(__DIR__).'/src';

    // The floor first: a scan whose needles had drifted would find no
    // pruning path AND no reference, and only the second makes the first
    // readable.
    expect(AppActionRetentionScan::referencesIn($root))->toBe([
        'Audit/AppActionEvent.php',
        'Audit/AppActionEventBuilder.php',
        'Audit/AppActionOutboxEntry.php',
        'Audit/AppActionRecorder.php',
    ]);

    // The one EMITTER is deliberately not in that list. `ConsoleEnter`
    // reaches the stream only through the recorder and never names
    // either model in code — which matters here because it does prune
    // something else (expired assertion burns), and a file naming both
    // would be flagged by a co-occurrence rule that cannot tell which
    // table a verb belongs to. That imprecision is real; keeping the
    // emitter off the models rather than exempting it is the answer
    // that does not weaken the scan.
    expect(AppActionRetentionScan::referencesIn($root))
        ->not->toContain('Http/Controllers/ConsoleEnter.php');

    expect(AppActionRetentionScan::scan($root))->toBe([]);
});

it('names a pruning path when the walk meets one', function (): void {
    // Proven able to fail, on the exact shape that would break the
    // declaration: a sweep somewhere in src/ that deletes rows from this
    // stream. The innocent halves are present too — a file that names
    // the stream and deletes nothing, and a file that deletes plenty and
    // names something else — because a scan that flagged either would be
    // unusable.
    $root = sys_get_temp_dir().'/bfc-app-action-retention-'.bin2hex(random_bytes(6));

    mkdir($root.'/Audit', 0700, true);

    $files = [
        $root.'/Audit/Innocent.php' => "<?php\n\nfinal class Innocent { public function read(): void { AppActionEvent::query()->count(); } }\n",
        $root.'/Audit/AlsoInnocent.php' => "<?php\n\nfinal class AlsoInnocent { public function sweep(): void { OtherModel::query()->delete(); } }\n",
        $root.'/Audit/Commented.php' => "<?php\n\n/** This never calls AppActionEvent::query()->delete() and never truncates. */\nfinal class Commented {}\n",
        $root.'/Audit/Sweeper.php' => "<?php\n\nfinal class Sweeper { public function prune(): void { AppActionEvent::query()->where('occurred_at', '<', 1)->delete(); } }\n",
    ];

    foreach ($files as $path => $contents) {
        file_put_contents($path, $contents);
    }

    try {
        expect(AppActionRetentionScan::scan($root))->toBe(['Audit/Sweeper.php' => ['->delete(']]);

        // The commented file names the stream only in a docblock, so it
        // is not even a REFERENCE: prose about never deleting must not
        // read as deleting.
        expect(AppActionRetentionScan::referencesIn($root))
            ->toBe(['Audit/Innocent.php', 'Audit/Sweeper.php']);
    } finally {
        array_map(unlink(...), array_keys($files));
        rmdir($root.'/Audit');
        rmdir($root);
    }
});

// ─── AC18: the capability, named for what ships ─────────────────────────────

it('advertises the app-action emit capability without promising a way to read the stream', function (): void {
    $capabilities = (array) $this->getJson('/bfc/meta')->assertOk()->json('capabilities');

    expect($capabilities)->toContain('app-action-audit-emit')
        // The name a control plane would read as "I can query this".
        ->and($capabilities)->not->toContain('app-action-audit');

    // And no route exists to read it, on any verb the contract uses.
    foreach (['get', 'post'] as $verb) {
        expect($this->{$verb.'Json'}('/bfc/console/audit')->status())->toBe(404);
    }
});
