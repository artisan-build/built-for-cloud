<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Audit\AppAction;
use ArtisanBuild\BuiltForCloud\Audit\AppActionActor;
use ArtisanBuild\BuiltForCloud\Audit\AppActionEvent;
use ArtisanBuild\BuiltForCloud\Audit\AppActionOutboxEntry;
use ArtisanBuild\BuiltForCloud\Audit\AppActionReason;
use ArtisanBuild\BuiltForCloud\Audit\AppActionRecorder;
use ArtisanBuild\BuiltForCloud\Audit\AppActorType;
use ArtisanBuild\BuiltForCloud\Audit\AppendOnlyBuilder;
use ArtisanBuild\BuiltForCloud\Audit\ConsoleAction;
use ArtisanBuild\BuiltForCloud\AuditActorType;
use ArtisanBuild\BuiltForCloud\Console\ActingPrincipalResolver;
use ArtisanBuild\BuiltForCloud\Console\ConsoleGuardConfiguration;
use ArtisanBuild\BuiltForCloud\Console\DelegatedActor;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialOutboxEntry;
use ArtisanBuild\BuiltForCloud\Tests\AppActionReadTransportScan;
use ArtisanBuild\BuiltForCloud\Tests\AppActionRetentionScan;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\ConsoleEventsDigest;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\ConsoleEventsLedger;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\ConsoleEventsReport;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\ConsoleEventsSource;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\ConsoleEventsTally;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\CountedAppAction;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\SinkAppAction;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\UnboundedAppAction;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\User;
use ArtisanBuild\BuiltForCloud\Tests\PublicSurfaceScan;
use Illuminate\Database\Eloquent\Builder;
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
    ?string $naturalKey = null,
    AppActionReason $reason = AppActionReason::Requested,
    AppAction $action = SinkAppAction::InvoiceVoided,
): AppActionEvent {
    $actor ??= AppActionActor::delegated(consoleActor(), 'Acme Agency');

    return DB::transaction(fn (): AppActionEvent => app(AppActionRecorder::class)->record(
        action: $action,
        actor: $actor,
        reason: $reason,
        naturalKey: $naturalKey,
    ));
}

/**
 * Record one app action inside a transaction the caller has ALREADY
 * opened, optionally keyed. `recordAppAction()` opens its own, which
 * would make two calls two transactions and hide both cases that use
 * this: keyless cross-call dedup, and the catch-and-commit pair.
 */
function recordAppActionInCurrentTransaction(?string $naturalKey = null): AppActionEvent
{
    return app(AppActionRecorder::class)->record(
        action: SinkAppAction::InvoiceVoided,
        actor: AppActionActor::delegated(consoleActor(), 'Acme Agency'),
        reason: AppActionReason::Requested,
        naturalKey: $naturalKey,
    );
}

/**
 * A well-formed row, as attributes, for the direct-model-write tests.
 * Every one of those tests breaks exactly ONE field of this, so what the
 * refusal is about is never in doubt.
 *
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function wellFormedAppActionRow(array $overrides = []): array
{
    return array_merge([
        'action' => SinkAppAction::InvoiceVoided->value,
        'action_vocabulary' => SinkAppAction::class,
        'reason' => AppActionReason::Requested->value,
        'actor_type' => AppActorType::DelegatedActor->value,
        'actor_ref' => DelegatedActor::IDENTIFIER_PREFIX.'7',
        'on_behalf_of' => null,
        'occurred_at' => now(),
    ], $overrides);
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

// ─── B1: the row guards itself, whoever writes it ───────────────────────────

it('refuses a direct model write that carries runtime prose as its action', function (): void {
    // THE BYPASS THIS EXISTS FOR. `AppActionRecorder` is the only path
    // the package offers, but it is not a gate PHP can close, and an
    // earlier revision called it "the single emission point" while
    // AppActionEvent::create() reached the same table with a request
    // value as its action name.
    expect(fn (): mixed => DB::transaction(fn (): AppActionEvent => AppActionEvent::query()->create(
        wellFormedAppActionRow([
            'action' => 'runtime prose from a request',
            'action_vocabulary' => 'not-an-enum',
        ]),
    )))->toThrow(LogicException::class, AppAction::class);

    expect(AppActionEvent::query()->count())->toBe(0);
});

it('refuses a direct model write whose action is not a case of the vocabulary it names', function (): void {
    // A REAL vocabulary and an identifier-shaped name that is not in it.
    // The marker interface alone does not make a slug a member of THIS
    // app's declared set — the same reasoning the vitals headline landed
    // on for a foreign label.
    expect(fn (): mixed => DB::transaction(fn (): AppActionEvent => AppActionEvent::query()->create(
        wellFormedAppActionRow(['action' => 'invoice-shredded']),
    )))->toThrow(LogicException::class, 'is not one of');

    expect(AppActionEvent::query()->count())->toBe(0);
});

it('refuses a direct model write that names a delegated actor by a bare id', function (): void {
    // AC6 at the ROW rather than only at the factory: actor 7 and user 7
    // both exist routinely, so a stored `7` would read as user 7 having
    // done it.
    expect(fn (): mixed => DB::transaction(fn (): AppActionEvent => AppActionEvent::query()->create(
        wellFormedAppActionRow(['actor_ref' => '7']),
    )))->toThrow(LogicException::class, 'type-qualified identity');

    expect(AppActionEvent::query()->count())->toBe(0);
});

it('refuses a direct model write that fabricates an agency for a local user', function (): void {
    // AC5's structural half. Defence in depth on the writes that fire
    // model events, not a boundary: only a delegated actor acts for an
    // agency.
    expect(fn (): mixed => DB::transaction(fn (): AppActionEvent => AppActionEvent::query()->create(
        wellFormedAppActionRow([
            'actor_type' => AppActorType::LocalUser->value,
            'actor_ref' => '7',
            'on_behalf_of' => 'Forged Agency',
        ]),
    )))->toThrow(LogicException::class, 'acts on behalf of an agency');

    expect(AppActionEvent::query()->count())->toBe(0);
});

it('persists a well-formed direct model write with no ledger row, which is the residue the recorder names', function (): void {
    // RENAMED: the old title began "refuses", and this body asserts the
    // opposite — the write SUCCEEDS, and that is the point.
    //
    // THE RESIDUE, asserted rather than only described. A direct write
    // that satisfies every row invariant still gets no ledger row — the
    // event id it would reference does not exist when `creating` runs —
    // so one event per caller-identified action is a property of the
    // recorder and of nothing else.
    DB::transaction(fn (): AppActionEvent => AppActionEvent::query()->create(wellFormedAppActionRow()));

    expect(AppActionEvent::query()->count())->toBe(1)
        ->and(AppActionOutboxEntry::query()->count())->toBe(0);
});

// ─── B3: the dedup ledger is protected as strongly as the event ─────────────

it('rejects update and delete on a ledger row at the model layer', function (): void {
    // A dedup record that can be deleted is not a dedup record: a unique
    // index only rejects a duplicate while the row it collides with
    // still exists.
    recordAppAction(naturalKey: 'invoice-42-voided');

    $row = AppActionOutboxEntry::query()->sole();

    expect(fn (): bool => $row->update(['dedup_key' => str_repeat('a', 64)]))
        ->toThrow(LogicException::class, 'append-only');

    expect(fn (): ?bool => $row->delete())
        ->toThrow(LogicException::class, 'append-only');

    expect(AppActionOutboxEntry::query()->count())->toBe(1);
});

it('rejects raw update and delete on the ledger table at the database layer on sqlite', function (): void {
    recordAppAction(naturalKey: 'invoice-42-voided');

    $row = AppActionOutboxEntry::query()->sole();

    expect(fn (): int => DB::table('bfc_app_action_outbox')->where('id', $row->id)->update(['dedup_key' => 'x']))
        ->toThrow(QueryException::class, 'append-only');

    expect(fn (): int => DB::table('bfc_app_action_outbox')->where('id', $row->id)->delete())
        ->toThrow(QueryException::class, 'append-only');

    expect(AppActionOutboxEntry::query()->count())->toBe(1);
})->skip(fn (): bool => DB::connection()->getDriverName() !== 'sqlite', 'database-layer enforcement is per-driver; this suite runs sqlite');

it('refuses a second ledger row for one event', function (): void {
    // "One ledger row per event" is a database property too, so neither
    // half of the pair can be quietly doubled.
    $event = recordAppAction(naturalKey: 'invoice-42-voided');

    expect(fn (): mixed => DB::transaction(fn (): AppActionOutboxEntry => AppActionOutboxEntry::query()->create([
        'event_id' => $event->id,
        'dedup_key' => str_repeat('b', 64),
    ])))->toThrow(UniqueConstraintViolationException::class);

    expect(AppActionOutboxEntry::query()->count())->toBe(1);
});

// ─── B4: the bulk paths the model events never see ──────────────────────────

it('refuses every enumerated bulk mutation on the app-action stream, on both models', function (): void {
    // Model events fire on INSTANCE operations only. A bulk
    // `->update([...])` or `->delete()` compiles straight to SQL and
    // fires nothing, so without the builder these would be caught by the
    // database triggers alone — and a driver this package writes no
    // triggers for would have no enforcement at all.
    recordAppAction(naturalKey: 'invoice-42-voided');

    // Every member of AppendOnlyBuilder::REFUSED, driven. Three
    // families: bulk writes that fire no model events, quiet creates
    // that MUTE the row's own validation, and event-free inserts —
    // `insertOrIgnore` above all, which would swallow the unique-index
    // violation one event per caller-identified action rests on.
    $mutations = [
        'createQuietly' => fn (Builder $q): mixed => $q->createQuietly(['action' => 'x']),
        'decrement' => fn (Builder $q): mixed => $q->decrement('id'),
        'decrementEach' => fn (Builder $q): mixed => $q->decrementEach(['id' => 1]),
        'delete' => fn (Builder $q): mixed => $q->delete(),
        'fillAndInsert' => fn (Builder $q): mixed => $q->fillAndInsert([['id' => 'x']]),
        'fillAndInsertGetId' => fn (Builder $q): mixed => $q->fillAndInsertGetId(['id' => 'x']),
        'fillAndInsertOrIgnore' => fn (Builder $q): mixed => $q->fillAndInsertOrIgnore([['id' => 'x']]),
        'forceCreateQuietly' => fn (Builder $q): mixed => $q->forceCreateQuietly(['action' => 'x']),
        'forceDelete' => fn (Builder $q): mixed => $q->forceDelete(),
        'increment' => fn (Builder $q): mixed => $q->increment('id'),
        'incrementEach' => fn (Builder $q): mixed => $q->incrementEach(['id' => 1]),
        'insertGetId' => fn (Builder $q): mixed => $q->insertGetId(['id' => 'x']),
        'insertOrIgnore' => fn (Builder $q): mixed => $q->insertOrIgnore([['id' => 'x']]),
        // The three the round-2 reviewer wrote and watched persist a
        // forged row: all reached the table through `Builder::__call()`
        // forwarding, which is why no list of names can be complete.
        'insertOrIgnoreReturning' => fn (Builder $q): mixed => $q->insertOrIgnoreReturning([['id' => 'x']]),
        'insertOrIgnoreUsing' => fn (Builder $q): mixed => $q->insertOrIgnoreUsing(['id'], 'select 1'),
        'insertUsing' => fn (Builder $q): mixed => $q->insertUsing(['id'], 'select 1'),
        'touch' => fn (Builder $q): mixed => $q->touch(),
        'truncate' => fn (Builder $q): mixed => $q->truncate(),
        'update' => fn (Builder $q): mixed => $q->update(['action' => 'rewritten-history']),
        'updateFrom' => fn (Builder $q): mixed => $q->updateFrom(['action' => 'rewritten-history']),
        'updateOrInsert' => fn (Builder $q): mixed => $q->updateOrInsert(['id' => 'x'], ['id' => 'x']),
        'upsert' => fn (Builder $q): mixed => $q->upsert([['id' => 'x']], ['id']),
    ];

    // The behavioural set and the declared enumeration are the same set:
    // a refusal added to the class without a test here, or a test here
    // for something the class does not refuse, reds this. It says
    // nothing about spellings NEITHER of them knows — that residue is
    // named on AppendOnlyBuilder and is why no guarantee rests on this
    // list being complete.
    expect(array_keys($mutations))->toBe(AppendOnlyBuilder::REFUSED);

    foreach ([AppActionEvent::class, AppActionOutboxEntry::class] as $model) {
        foreach ($mutations as $name => $mutate) {
            expect(fn (): mixed => $mutate($model::query()))
                ->toThrow(LogicException::class, 'append-only', "{$model}::query()->{$name}() was not refused");
        }
    }

    // Nothing was mutated, removed or added by any of them.
    expect(AppActionEvent::query()->count())->toBe(1)
        ->and(AppActionOutboxEntry::query()->count())->toBe(1)
        ->and(AppActionEvent::query()->sole()->action)->toBe(SinkAppAction::InvoiceVoided->value);
});

it('pins the exact set of operations the append-only builder refuses', function (): void {
    // The enumeration IS the claim, so it is pinned: removing an
    // override — or a framework upgrade adding a mutator this class has
    // never heard of — has to be a deliberate diff rather than a quiet
    // one. Inserts are deliberately absent; the model's own save path
    // goes through Builder::insert() for a non-incrementing key, and
    // that residue is named on the builder.
    // Declared on the class itself, not inherited: `PublicSurfaceScan`
    // reports the whole public surface, and the whole public surface of
    // an Eloquent builder is a hundred query methods.
    $declared = array_values(array_map(
        static fn (ReflectionMethod $method): string => $method->getName(),
        array_filter(
            (new ReflectionClass(AppendOnlyBuilder::class))->getMethods(ReflectionMethod::IS_PUBLIC),
            static fn (ReflectionMethod $method): bool => $method->getDeclaringClass()->getName() === AppendOnlyBuilder::class,
        ),
    ));

    sort($declared);

    expect($declared)->toBe(AppendOnlyBuilder::REFUSED)
        // …and the scan that reports the FULL surface still sees them,
        // so the filter above cannot be hiding a method from itself.
        ->and(PublicSurfaceScan::of(AppendOnlyBuilder::class))
        ->toContain(...AppendOnlyBuilder::REFUSED);

    // `insert()` is the one mutating spelling deliberately left alone —
    // `Model::performInsert()` uses it for a non-incrementing key, so
    // refusing it would refuse the package's own writes.
    expect($declared)->not->toContain('insert');
});

it('has exactly the public surface it is meant to have on the emission point', function (): void {
    // `dedupKeyFor()` is PUBLIC on purpose (its own docblock says why),
    // and this is what makes that a decision rather than an accident: it
    // was promoted from a private helper to serve a test, and a helper
    // that becomes public to serve a test is how a package acquires
    // surface nobody chose. The enumeration means the NEXT one cannot
    // arrive the same way — adding a public method here reds this test,
    // and whoever adds it extends the set in the same diff.
    //
    // WHAT THIS DOES NOT CATCH, since that is a claim too: it reads
    // method NAMES, so it says nothing about a change to what `record()`
    // or `dedupKeyFor()` DOES, nothing about their signatures, and
    // nothing about a public method added to any other class. The
    // digest's stability under the name is pinned by the digest tests
    // above and by `tests/ConsoleEnterAuditTest.php`.
    $expected = ['dedupKeyFor', 'record'];

    expect(PublicSurfaceScan::of(AppActionRecorder::class))->toBe($expected)
        ->and(PublicSurfaceScan::unexpectedIn(AppActionRecorder::class, $expected))->toBe([])
        ->and(PublicSurfaceScan::missingFrom(AppActionRecorder::class, $expected))->toBe([]);
});

// ─── A8: the dedup key is a digest, not an app-content channel ──────────────

it('stores a digest rather than the caller\'s natural key', function (): void {
    // A caller's string written verbatim into the column would be an
    // app-content channel into a stream whose whole premise is that no
    // app content enters it — an app can pass a request value straight
    // in, and a future consumer of this schema would discover it had one.
    recordAppAction(naturalKey: 'invoice 42 <script>alert(1)</script>');

    $key = AppActionOutboxEntry::query()->sole()->dedup_key;

    expect($key)->toMatch('/^[0-9a-f]{64}$/')
        ->and($key)->not->toContain('invoice')
        ->and($key)->not->toContain('script');
});

it('namespaces the digest by vocabulary and action, so two vocabularies sharing a natural key do not collide', function (): void {
    // The previous revision held every app's keys in one flat string
    // space, so two unrelated vocabularies choosing the same natural key
    // silently suppressed each other's events.
    DB::transaction(function (): void {
        app(AppActionRecorder::class)->record(
            action: SinkAppAction::InvoiceVoided,
            actor: AppActionActor::delegated(consoleActor(), null),
            reason: AppActionReason::Requested,
            naturalKey: 'shared-key',
        );

        // Same natural key, a different action in a different
        // vocabulary. Under the old flat key space this second insert
        // failed and took the transaction with it.
        app(AppActionRecorder::class)->record(
            action: ConsoleAction::ConsoleEntered,
            actor: AppActionActor::delegated(consoleActor(), null),
            reason: AppActionReason::ConsoleEntry,
            naturalKey: 'shared-key',
        );
    });

    expect(AppActionEvent::query()->count())->toBe(2)
        ->and(AppActionOutboxEntry::query()->distinct()->count('dedup_key'))->toBe(2);

    // …and two actions from the SAME vocabulary sharing a key are
    // likewise distinct, so the namespace is the pair and not just the class.
    DB::transaction(function (): void {
        app(AppActionRecorder::class)->record(
            action: SinkAppAction::TeammateInvited,
            actor: AppActionActor::delegated(consoleActor(), null),
            reason: AppActionReason::Requested,
            naturalKey: 'shared-key',
        );
    });

    expect(AppActionOutboxEntry::query()->distinct()->count('dedup_key'))->toBe(3);
});

it('refuses a ledger row whose dedup key is not digest-shaped, and accepts one that merely looks like a digest', function (): void {
    // RENAMED and extended. The old title said "is not a digest"; the
    // check can only see the SHAPE of one, and the round-2 reviewer
    // demonstrated the difference by storing sixty-four literal `a`
    // characters. Both halves are driven here, so the limit is pinned
    // rather than described.
    //
    // It cannot be otherwise: verifying that a key IS a digest needs the
    // caller's natural key, which is deliberately not stored — storing
    // it is the app-content channel this column exists to avoid. What
    // makes a key real is that AppActionRecorder::dedupKeyFor() computed
    // it, which is a property of the recorder path and not of the table.
    $event = recordAppAction(naturalKey: 'invoice-42-voided');

    // A slug is refused…
    expect(fn (): mixed => DB::transaction(fn (): AppActionOutboxEntry => AppActionOutboxEntry::query()->create([
        'event_id' => $event->id,
        'dedup_key' => 'invoice 42 <script>alert(1)</script>',
    ])))->toThrow(LogicException::class, 'not a caller\'s string');

    expect(AppActionOutboxEntry::query()->count())->toBe(1);

    // …and sixty-four literal `a` characters are ACCEPTED, because they
    // are digest-shaped. That is the residue, and it is why no guarantee
    // rests on this check.
    $orphan = DB::transaction(fn (): AppActionEvent => AppActionEvent::query()->create(wellFormedAppActionRow()));

    DB::transaction(fn (): AppActionOutboxEntry => AppActionOutboxEntry::query()->create([
        'event_id' => $orphan->id,
        'dedup_key' => str_repeat('a', 64),
    ]));

    expect(AppActionOutboxEntry::query()->where('event_id', $orphan->id)->sole()->dedup_key)
        ->toBe(str_repeat('a', 64));
});

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

it('pairs each recorded event with exactly one ledger row carrying a digest key', function (): void {
    // RENAMED from a title that said "in the caller's own transaction",
    // which this body never asserted. The transactional half is driven
    // where it can be — `tests/RecorderTransactionGuardTest.php`, which
    // runs without RefreshDatabase — and by "leaves neither the event nor
    // its ledger row behind when the action rolls back". What THIS pins
    // is the pairing and the key's shape.
    $event = recordAppAction(naturalKey: 'invoice-42-voided');

    $ledger = AppActionOutboxEntry::query()->sole();

    expect($ledger->event_id)->toBe($event->id)
        ->and(AppActionOutboxEntry::query()->count())->toBe(1)
        // A digest of the vocabulary, the action and the natural key —
        // never the natural key itself. See "stores a digest rather than
        // the caller's natural key" for why that matters.
        ->and($ledger->dedup_key)->toMatch('/^[0-9a-f]{64}$/');
});

it('leaves neither the event nor its ledger row behind when the action rolls back', function (): void {
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

// ─── AC11: one event per CALLER-IDENTIFIED action ───────────────────────────
//
// The condition is the guarantee: a caller that supplies a natural key
// gets the duplicate refused; a caller that supplies none is keyed to its
// own event id and gets no cross-call deduplication at all. Stated in
// full on `AppActionRecorder::record()`, and driven below in both
// directions — the keyed one and the keyless one.

it('refuses a second emission of the same logical action, and takes the transaction with it', function (): void {
    $failed = false;

    try {
        DB::transaction(function (): void {
            foreach ([1, 2] as $ignored) {
                app(AppActionRecorder::class)->record(
                    action: SinkAppAction::InvoiceVoided,
                    actor: AppActionActor::delegated(consoleActor(), null),
                    reason: AppActionReason::Requested,
                    naturalKey: 'invoice-42-voided',
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
    recordAppAction(naturalKey: 'invoice-42-voided');
    recordAppAction(naturalKey: 'invoice-43-voided');

    expect(AppActionEvent::query()->count())->toBe(2);
});

// The pair is atomic with ITSELF, and this is the case that proves it
// rather than describing it. The duplicate test above lets the exception
// escape `DB::transaction()`, so the caller's own rollback hides whether
// the recorder did anything: an app that CATCHES the failure inside its
// transaction and commits anyway used to keep an event row with no
// ledger row (observed: two events, one ledger row). The savepoint
// inside `record()` is what closes it.
it('keeps the event and its ledger row atomic when the caller catches the failure and commits anyway', function (): void {
    DB::transaction(function (): void {
        recordAppActionInCurrentTransaction(naturalKey: 'invoice-42-voided');

        try {
            recordAppActionInCurrentTransaction(naturalKey: 'invoice-42-voided');
        } catch (UniqueConstraintViolationException) {
            // The app swallows it and commits anyway — which is its
            // right, and which must not be able to leave a half-pair
            // behind.
        }
    });

    // The FIRST emission survives, because it succeeded and the caller
    // committed. The second left nothing at all.
    expect(AppActionEvent::query()->count())->toBe(1)
        ->and(AppActionOutboxEntry::query()->count())->toBe(1);
});

// The OTHER direction of AC11, and the one the guarantee's condition is
// about. Without it the sentence above reads as unconditional — which is
// exactly what it read as through three review rounds, while a green
// suite watched: every existing case passed a natural key, so nothing
// here could tell "the recorder dedupes" from "the recorder dedupes when
// the caller names the action".
it('dedupes nothing across calls when the caller supplies no natural key', function (): void {
    // The SAME logical action, twice, keyed by nothing. Each call hashes
    // its own fresh event id, so the two ledger rows do not collide and
    // both emissions succeed — one event and one ledger row per CALL,
    // and no cross-call deduplication at all.
    DB::transaction(function (): void {
        recordAppActionInCurrentTransaction();
        recordAppActionInCurrentTransaction();
    });

    expect(AppActionEvent::query()->count())->toBe(2)
        ->and(AppActionOutboxEntry::query()->count())->toBe(2)
        ->and(AppActionOutboxEntry::query()->distinct()->count('dedup_key'))->toBe(2);
});

// ─── AC15: declared retention — nothing prunes this stream ──────────────────

it('finds no enumerated deletion spelling against the app-action stream anywhere in src', function (): void {
    $root = dirname(__DIR__).'/src';

    // The floor first: a walk whose needles had drifted would find no
    // deletion spelling AND no reference, and only the second makes the
    // first readable.
    expect(AppActionRetentionScan::referencesIn($root))->toBe([
        'Audit/AppActionEvent.php',
        // The class name of the event's own builder contains the model's,
        // which is how a textual walk sees it. Harmless, and left in the
        // expectation rather than filtered out: the list is what the walk
        // reports, not a curated version of it.
        'Audit/AppActionEventBuilder.php',
        'Audit/AppActionOutboxEntry.php',
        'Audit/AppActionRecorder.php',
    ]);

    // The one EMITTER is deliberately not in that list, and its absence
    // is luck rather than enforcement — which is worth asserting so the
    // day it changes, somebody reads why. `ConsoleEnter` prunes expired
    // assertion burns and reaches this stream only through the recorder,
    // so it names no model; a type hint added tomorrow would put it in
    // the walk and report a deletion that has nothing to do with this
    // stream. The answer to that is NOT a file exemption — an exemption
    // on the sole emitter is the blind spot the walk exists to prevent —
    // it is to keep the emitter off the models, or to accept the red and
    // decide deliberately.
    expect(AppActionRetentionScan::referencesIn($root))
        ->not->toContain('Http/Controllers/ConsoleEnter.php');

    expect(AppActionRetentionScan::scan($root))->toBe([]);
});

it('names every enumerated deletion spelling when the walk meets one', function (): void {
    // ONE POSITIVE CONTROL PER SPELLING, because a list is only worth
    // what its weakest member is: the previous revision of this walk was
    // missing `::destroy(`, `->deleteQuietly(` and the whole Prunable
    // family, and a single `->delete(` fixture reported "proven able to
    // fail" while three real deletion paths sat outside it.
    //
    // `deleteQuietly()` earns its place twice over: it fires no model
    // events, so it slips past the append-only guards entirely and is
    // caught only by the database triggers.
    $root = sys_get_temp_dir().'/bfc-app-action-retention-'.bin2hex(random_bytes(6));

    mkdir($root.'/Audit', 0700, true);

    /** @var array<string, array{0: string, 1: list<string>}> $spellings */
    $spellings = [
        'Delete' => ['AppActionEvent::query()->delete();', ['->delete(']],
        'Destroy' => ['AppActionEvent::destroy([1]);', ['::destroy(']],
        'DeleteQuietly' => ['$row->deleteQuietly();', ['->deleteQuietly(']],
        'ForceDelete' => ['$row->forceDelete();', ['->forceDelete(']],
        'ForceDeleteQuietly' => ['$row->forceDeleteQuietly();', ['->forceDeleteQuietly(']],
        'BuilderTruncate' => ['AppActionEvent::query()->truncate();', ['->truncate(']],
        'StaticTruncate' => ['AppActionEvent::truncate();', ['::truncate(']],
        'InstancePrune' => ['$this->prune(1);', ['->prune(']],
        'StaticPrune' => ['AppActionEvent::prune(1);', ['::prune(']],
        'InstancePruneAll' => ['$this->pruneAll();', ['->pruneAll(']],
        'StaticPruneAll' => ['AppActionEvent::pruneAll();', ['::pruneAll(']],
        // A trait name, not a call site: a model that uses either has a
        // pruning path whether or not it spells `prune(` anywhere,
        // because `model:prune` calls it. MassPrunable contains
        // Prunable, so it matches both — asserted rather than special-cased.
        'MassPruned' => ['$x = MassPrunable::class;', ['MassPrunable', 'Prunable']],
        'Pruned' => ['$x = Prunable::class;', ['Prunable']],
        'InstanceDropIfExists' => ['$schema->dropIfExists($t);', ['->dropIfExists(']],
        'DropIfExists' => ['Schema::dropIfExists($t);', ['::dropIfExists(']],
        'Drop' => ['Schema::drop($t);', ['::drop(']],
    ];

    $files = [
        // The two innocent halves, because a walk that flagged either
        // would be unusable: a file that names the stream and deletes
        // nothing, and a file that deletes plenty and names something else.
        $root.'/Audit/Innocent.php' => "<?php\n\nfinal class Innocent { public function read(): void { AppActionEvent::query()->count(); } }\n",
        $root.'/Audit/AlsoInnocent.php' => "<?php\n\nfinal class AlsoInnocent { public function sweep(): void { OtherModel::query()->delete(); } }\n",
        // Prose about never deleting must not read as deleting.
        $root.'/Audit/Commented.php' => "<?php\n\n/** This never calls AppActionEvent::query()->delete() and never truncates. */\nfinal class Commented {}\n",
    ];

    $expected = [];

    foreach ($spellings as $name => [$statement, $hits]) {
        $files[$root.'/Audit/'.$name.'.php'] =
            "<?php\n\nfinal class {$name} { public function go(): void { \$t = 'bfc_app_action_events'; {$statement} } }\n";

        $expected['Audit/'.$name.'.php'] = $hits;
    }

    ksort($expected);

    foreach ($files as $path => $contents) {
        file_put_contents($path, $contents);
    }

    try {
        // Every spelling is named, and the innocent files are not.
        expect(AppActionRetentionScan::scan($root))->toBe($expected);

        expect(AppActionRetentionScan::referencesIn($root))
            ->toContain('Audit/Innocent.php')
            ->not->toContain('Audit/AlsoInnocent.php')
            ->not->toContain('Audit/Commented.php');

        // And the enumeration in the scan is exactly the set these
        // fixtures drive: a needle added without a control reds this.
        $driven = array_values(array_unique(array_merge(...array_values($expected))));
        sort($driven);
        $enumerated = AppActionRetentionScan::PRUNE_NEEDLES;
        sort($enumerated);

        expect($driven)->toBe($enumerated);
    } finally {
        array_map(unlink(...), array_keys($files));
        rmdir($root.'/Audit');
        rmdir($root);
    }
});

// ─── AC18: the capability, named for what ships ─────────────────────────────

it('advertises the app-action emit capability without promising a way to read the stream', function (): void {
    $capabilities = (array) $this->getJson('/bfc/meta')->assertOk()->json('capabilities');

    expect($capabilities)->toContain('app-action-audit-emit');

    // WHAT REPLACED THE URI PIN, AND WHY. The previous revision matched
    // registered URIs against `/app.?action|audit/i` and asserted the
    // set was empty; its positive control mounted
    // `/bfc/console/app-actions` and watched the regex report it, which
    // proves the regex works and says nothing about the claim. A
    // package controller at `/bfc/console/events` listing
    // `AppActionEvent` rows was invisible to it while the contract's
    // sentence stayed green — the third time on this build that a check
    // deciding on a SPELLING could not see the thing that was missing.
    //
    // So the classification is over what a route REACHES, and every
    // registered route is visited and bucketed rather than selected.
    // The floor first, because a scan that enumerated nothing would
    // report an empty read-transport list too.
    $classified = AppActionReadTransportScan::classify(Route::getRoutes()->getRoutes());

    expect(count($classified))->toBeGreaterThan(20)
        ->and($classified)->toHaveKey('POST /bfc/console/enter');

    // The one route that legitimately touches the stream is the door,
    // and it is classified as writing rather than exempted by name: an
    // exemption on the sole emitter is the blind spot the enumeration
    // exists to prevent.
    expect($classified['POST /bfc/console/enter'])->toBe(AppActionReadTransportScan::EMITS);

    expect(AppActionReadTransportScan::readTransportsIn(Route::getRoutes()->getRoutes()))->toBe([]);
});

it('names a route that reads the app-action stream under a name that mentions neither', function (): void {
    // PROVEN ABLE TO FAIL, on the route the old pin was blind to. None
    // of these three paths or class names contains `app-action` or
    // `audit`, and the old URI heuristic reports every one of them as
    // clean.
    Route::get('/bfc/console/events', ConsoleEventsDigest::class);
    Route::get('/bfc/console/summary', ConsoleEventsReport::class);
    Route::get('/bfc/console/tally', ConsoleEventsTally::class);
    // D4: PHP resolves class names case-insensitively and the first
    // revision of the matcher did not, so this spelling reached the
    // model and was reported as reaching nothing. The table name in it
    // is folded too.
    Route::get('/bfc/console/ledger', ConsoleEventsLedger::class);

    // The heuristic this replaces, run over the same routes, to show
    // that the fixtures genuinely defeat it rather than being caught by
    // both instruments.
    $byUri = array_values(array_filter(
        ['/bfc/console/events', '/bfc/console/summary', '/bfc/console/tally'],
        static fn (string $uri): bool => preg_match('/app.?action|audit/i', $uri) === 1,
    ));

    expect($byUri)->toBe([]);

    expect(AppActionReadTransportScan::readTransportsIn(Route::getRoutes()->getRoutes()))->toBe([
        'GET /bfc/console/events',
        'GET /bfc/console/ledger',
        'GET /bfc/console/tally',
    ]);

    // AND THE THIRD ONE IS THE BOUND, asserted where it lands rather
    // than described in a docblock. `/bfc/console/summary` reads the
    // stream through a class that is not part of this package, and the
    // walk follows the names of PACKAGE classes only — so it is
    // classified `unrelated` and this scan does not see it.
    //
    // That is the right scope for the sentence being held (the contract
    // claims what THIS RELEASE ships, and an app's own listing over its
    // own tables is the app's), and it is also the honest limit: a
    // package route delegating to a host-supplied collaborator is
    // outside the walk. The same read one hop through a package class
    // IS followed, which is what the next test drives.
    expect(AppActionReadTransportScan::classify(Route::getRoutes()->getRoutes()))
        ->toHaveKey('GET /bfc/console/summary')
        ->and(AppActionReadTransportScan::classify(Route::getRoutes()->getRoutes())['GET /bfc/console/summary'])
        ->toBe(AppActionReadTransportScan::UNRELATED);
});

it('follows a read one class past the route, and stops at the emission door', function (): void {
    // The two halves of the walk, driven directly rather than through
    // the router, over a fixture class map — so both are asserted on
    // classes this test names rather than on whatever `src/` happens to
    // contain today.
    $classes = [
        'AppActionEvent' => AppActionEvent::class,
        'AppActionRecorder' => AppActionRecorder::class,
        'ConsoleEventsSource' => ConsoleEventsSource::class,
    ];

    // One hop: the controller names no model, the class it delegates to
    // does. A direct-reference check passes this.
    expect(AppActionReadTransportScan::namesIn(
        (string) file_get_contents(__DIR__.'/Fixtures/ConsoleEventsReport.php'),
        $classes,
    ))->toBe([ConsoleEventsSource::class])
        ->and(AppActionReadTransportScan::bucketFor(ConsoleEventsReport::class, $classes))
        ->toBe(AppActionReadTransportScan::READS);

    // And the door STOPS the walk. The recorder names both models, so a
    // walk that passed through it would report `ConsoleEnter` — the one
    // route that is supposed to touch this stream — as a read
    // transport, and the answer to that would have been an exemption on
    // exactly the wrong route.
    expect(AppActionReadTransportScan::reachableFrom(AppActionRecorder::class))
        ->toBe([])
        ->and(AppActionReadTransportScan::namesIn(
            AppActionReadTransportScan::codeOf(AppActionRecorder::class),
            $classes,
        ))->toContain(AppActionEvent::class);
});

it('pins the emission door\'s public surface, so a verb cannot be ADDED to it unnoticed', function (): void {
    // WHAT THIS PIN CATCHES, SAID EXACTLY: an ADDITION. A third public
    // method, or either of these two changing its return type, reds
    // this. It says nothing about what the existing two DO — the bodies
    // are not read here — so a `record()` that kept its name and
    // signature and started returning a queried row would leave this
    // green. That direction is the next test's, behaviourally.
    expect(PublicSurfaceScan::of(AppActionRecorder::class))
        ->toBe(['dedupKeyFor', 'record']);

    $returns = [];

    foreach ((new ReflectionClass(AppActionRecorder::class))->getMethods(ReflectionMethod::IS_PUBLIC) as $method) {
        $returns[$method->getName()] = (string) $method->getReturnType();
    }

    ksort($returns);

    expect($returns)->toBe([
        'dedupKeyFor' => 'string',
        'record' => AppActionEvent::class,
    ]);
});

it('runs no read against the stream on either of the emission door\'s verbs', function (): void {
    // D5, AND IT IS THE PREMISE THE WHOLE WALK RESTS ON. The scan stops
    // at AppActionRecorder, so if the recorder could be used to READ,
    // every route that emits would be a read transport and the scan
    // would report clean. The surface pin above cannot establish that:
    // `record(...): AppActionEvent` can be rewritten to query and return
    // an existing row without changing its name, its signature or its
    // return type.
    //
    // So this reads what the verbs execute THROUGH THE CONNECTION'S
    // QUERY LOG, and that is the whole of what it reads. A `record()`
    // that fetched a row through the query builder, Eloquent or
    // `DB::select()` before returning it would be named here.
    //
    // WHAT IT DOES NOT SEE, and this sentence exists because the
    // sentence it replaces did not have it: a read issued directly on
    // the PDO handle — `DB::connection()->getPdo()->query(...)` —
    // returns the row and leaves the log empty, so a recorder written
    // that way passes this test. The previous wording here said "every
    // statement each one issues is captured", which was the SIXTH
    // completeness sentence this PR has had to withdraw and the fourth
    // round in which a correction wrote a new one. The log is a
    // tripwire over the ordinary spelling, not a proof about every way
    // a row can be read.
    $selects = static function (callable $call): array {
        DB::flushQueryLog();
        DB::enableQueryLog();

        try {
            $call();
        } finally {
            DB::disableQueryLog();
        }

        return array_values(array_filter(
            array_map(static fn (array $entry): string => (string) $entry['raw_query'], DB::getRawQueryLog()),
            static fn (string $sql): bool => preg_match('/^\s*select\b/i', $sql) === 1
                && preg_match('/\bbfc_app_action_(events|outbox)\b/i', $sql) === 1,
        ));
    };

    // The actor is built OUTSIDE the measured call: recording a handoff
    // writes and reads the delegated-actor table, and those statements
    // belong to the fixture rather than to the verb under test.
    $actor = AppActionActor::delegated(consoleActor(), 'Acme Agency');

    expect($selects(static fn (): string => AppActionRecorder::dedupKeyFor(
        SinkAppAction::InvoiceVoided,
        'invoice-1',
    )))->toBe([]);

    expect($selects(static fn (): AppActionEvent => DB::transaction(
        static fn (): AppActionEvent => app(AppActionRecorder::class)->record(
            action: SinkAppAction::InvoiceVoided,
            actor: $actor,
            reason: AppActionReason::Requested,
            naturalKey: 'invoice-2',
        ),
    )))->toBe([]);

    // THE CONTROL, because a query log that captured nothing would
    // satisfy both assertions above whatever the verbs did. A read of
    // the same tables through the same harness IS reported.
    expect($selects(static fn (): int => AppActionEvent::query()->count()))
        ->toHaveCount(1);

    expect($selects(static fn (): int => AppActionOutboxEntry::query()->count()))
        ->toHaveCount(1);
});
