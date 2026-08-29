<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Audit;

use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\MetadataShape;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use LogicException;

/**
 * The single emission point of the app-action audit stream (Console PRD
 * D17): one call appends the event row AND its outbox row, and REQUIRES
 * the caller's open database transaction.
 *
 * **THE STREAM IS TRANSACTIONAL OR IT IS FICTION** — the same ruling
 * {@see LifecycleEventRecorder} already carries, and for the same
 * reason. An action that rolls back takes its event and its outbox row
 * with it, so nothing is ever recorded about something that did not
 * happen; an event written outside the action's transaction is a record
 * that can outlive the thing it records. Outside a transaction this
 * throws rather than opening one of its own: a transaction this class
 * opened would commit independently of the caller's, which is precisely
 * the failure the requirement exists to prevent.
 *   Pinned by `tests/AppActionAuditTest.php` — "refuses to record an app
 *   action outside a database transaction" and "leaves neither the event
 *   nor its outbox row behind when the action rolls back".
 *
 * **THE ACTION IS AN ENUM CASE, AND THE TYPE IS THE ENFORCEMENT.** The
 * parameter is typed {@see AppAction}, which extends `BackedEnum`, so a
 * string cannot be passed at all — a `list<string>` of permitted names
 * would have been convention, and an app could have supplied it from
 * `Tag::pluck('slug')`. What a type cannot decide is whether the CASE
 * itself is bounded, so this method also refuses any case whose backing
 * value is not a {@see MetadataShape::TOKEN}: an app can write prose
 * into a case, and `case Whatever = 'whatever the operator typed today'`
 * is compile-time and still carries free text. The refusal is total —
 * the emission fails and the caller's transaction fails with it —
 * because storing a trimmed version of a value the contract forbids
 * would put the package's name on it.
 *   Pinned by `tests/AppActionAuditTest.php` — "refuses an action whose
 *   case is backed by prose rather than a bounded identifier", "refuses
 *   an action backed by an integer rather than an identifier" and
 *   "cannot be handed a free-text action at all, because the parameter
 *   is typed".
 *
 * **NO DRAIN, AND NO POST-COMMIT HOOK OF ANY KIND.** The credential
 * recorder hangs a synchronous drain off `DB::afterCommit()`; this one
 * does not, because this stream HAS no drainer
 * ({@see AppActionOutboxEntry} says why) — there is nothing to deliver
 * to, and a hook that called nothing would be a moving part pretending
 * to be a guarantee. The reasoning that would apply even once a consumer
 * exists is worth stating now, because the decision will be re-opened
 * then: the first emitter is `POST /bfc/console/enter`, a page-load path
 * an operator waits on, and a drain is O(claimable rows) and may send
 * mail — hanging one off the door's redirect buys nothing and costs the
 * operator's first paint. The refusal path on that same route already
 * declines a drain for the harder version of the same argument.
 *
 * @see AppActionEvent for the append-only guarantee and its residue
 */
final class AppActionRecorder
{
    /**
     * Append one app-action event and its outbox row, inside the
     * caller's transaction.
     *
     * `$dedupKey` is what makes "exactly one event per action" a
     * database property: it is UNIQUE on the outbox, so a second
     * emission of the same logical action fails the insert. It defaults
     * to the event's own id, which dedupes nothing — that default is for
     * an emitter whose action has no natural key, and such an emitter
     * gets no duplicate protection, which is the honest reading of "this
     * action has no identity". An emitter that CAN name its action
     * passes a key.
     *
     * @throws LogicException outside a transaction, or on an action whose case
     *                        is not backed by a bounded identifier
     */
    public function record(
        AppAction $action,
        AppActionActor $actor,
        AppActionReason $reason,
        ?string $dedupKey = null,
    ): AppActionEvent {
        if (DB::transactionLevel() === 0) {
            throw new LogicException(
                'App-action events record inside the action\'s own transaction, never outside one.',
            );
        }

        $name = $action->value;

        if (! is_string($name) || ! MetadataShape::isToken($name)) {
            throw new LogicException(
                'An app action is named by a bounded identifier from a compile-time vocabulary; '
                .$action::class.' backs a case with something else.',
            );
        }

        $event = AppActionEvent::query()->create([
            'id' => (string) Str::uuid(),
            'action' => $name,
            // WHICH vocabulary the name came from. Two apps may both
            // declare `invoice-voided` and mean different things, and a
            // bare slug leaves a reader unable to tell — while the enum
            // class is a compile-time constant, not runtime data.
            'action_vocabulary' => $action::class,
            'reason' => $reason,
            'actor_type' => $actor->type,
            'actor_ref' => $actor->ref,
            'on_behalf_of' => $actor->onBehalfOf,
            'occurred_at' => now(),
        ]);

        // A duplicate dedup key fails this insert — and with it the whole
        // transaction, the action included. That is the intended shape:
        // the same logical action is never recorded, and so never
        // delivered, twice.
        AppActionOutboxEntry::query()->create([
            'id' => (string) Str::uuid(),
            'event_id' => $event->id,
            'dedup_key' => $dedupKey ?? $event->id,
        ]);

        return $event;
    }
}
