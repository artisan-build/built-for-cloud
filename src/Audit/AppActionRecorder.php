<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Audit;

use ArtisanBuild\BuiltForCloud\Console\AssertionBurn;
use ArtisanBuild\BuiltForCloud\Console\DelegatedActor;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use LogicException;

/**
 * The package's emission point for the app-action audit stream (Console
 * PRD D17): one call appends the event row AND its dedup ledger row, in
 * the caller's own transaction.
 *
 * **THIS CLASS IS THE BOUNDARY THE STREAM'S GUARANTEES ARE ABOUT.**
 * Every one of them — a bounded action from a compile-time vocabulary, a
 * type-qualified actor, an agency only on a delegated actor, a
 * package-generated id, a transactional emission, exactly one event per
 * action, a digest dedup key — holds of **what is written through
 * `record()`**. Read as a claim about the TABLE, every one of them is
 * false, and two earlier revisions of this docblock read that way: the
 * first called this "the single emission point", the second moved the
 * claim onto the model's `creating` hook and said it held "for every
 * path that goes through the model".
 *
 * **Neither was true, and the second could not be made true.**
 * {@see AppActionEvent} is a public Eloquent model in the consuming
 * app's own database. `insert()`, `saveQuietly()`,
 * `Model::withoutEvents()`, `toBase()`, a raw `DB::table(...)` write,
 * and any builder spelling that forwards through `Builder::__call()` all
 * reach the table without firing a model event — and every review round
 * that chased that list found a spelling the previous round had missed.
 * An enumeration of a framework's surface does not terminate, and while
 * it is being chased the claim beside it is false.
 *
 * So the claim is narrowed rather than the test escalated: **an app
 * holding the model can write its own database directly, and the package
 * neither prevents nor detects that. What the package guarantees is what
 * the package writes.** The model's `creating` hook and
 * {@see AppendOnlyBuilder}'s refusal list are kept as defence in depth —
 * they catch the ordinary mistake, which is worth catching — and no
 * claim depends on either being complete.
 *
 * **THE STREAM IS TRANSACTIONAL OR IT IS FICTION** — the same ruling
 * {@see LifecycleEventRecorder} already carries, and for the same
 * reason. An action that rolls back takes its event and its ledger row
 * with it, so nothing is ever recorded about something that did not
 * happen; an event written outside the action's transaction is a record
 * that can outlive the thing it records. The check lives on the MODEL
 * rather than here, so it also catches a direct `create()` — defence in
 * depth, on the writes that fire model events, and not a boundary. This
 * class opens no transaction of its own: one it opened would commit
 * independently of the caller's, which is precisely the failure the
 * requirement exists to prevent.
 *   Pinned by `tests/RecorderTransactionGuardTest.php` — "refuses to
 *   record an app action outside a database transaction" and "refuses a
 *   direct model write made outside a transaction". Both live there
 *   because RefreshDatabase wraps every test it touches in a
 *   transaction, which would make the case under test unreachable.
 *
 *   Pinned by `tests/AppActionAuditTest.php` — "leaves neither the event
 *   nor its ledger row behind when the action rolls back".
 *
 * **THE ACTION IS AN ENUM CASE, AND ON THIS PATH THE TYPE IS THE
 * ENFORCEMENT.** The parameter is typed {@see AppAction}, which extends
 * `BackedEnum`, so a string cannot be passed at all — a `list<string>`
 * of permitted names would have been convention, and an app could have
 * supplied it from `Tag::pluck('slug')`. That is a statement about THIS
 * method's signature, and the signature is the enforcement for this
 * path. The model's own refusal checks the stored value rather than the
 * caller's type, which catches a direct `create()` and nothing that
 * bypasses model events.
 *   Pinned by `tests/AppActionAuditTest.php` — "refuses an action whose
 *   case is backed by prose rather than a bounded identifier", "refuses
 *   an action backed by an integer rather than an identifier" and
 *   "cannot be handed a free-text action at all, because the parameter
 *   is typed".
 *
 * **NO DRAIN, AND NO POST-COMMIT HOOK OF ANY KIND.** The credential
 * recorder hangs a synchronous drain off `DB::afterCommit()`; this one
 * does not, because this stream has no drainer
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
 * @see AppActionEvent for the append-only guarantee, its three layers and its residue
 */
final class AppActionRecorder
{
    /**
     * Append one app-action event and its dedup ledger row, inside the
     * caller's transaction.
     *
     * `$naturalKey` is the caller's own name for THIS action — an
     * invoice id, a mint digest — and it is what makes "exactly one
     * event per action" mean anything: it is hashed into the ledger's
     * unique `dedup_key`, so a second emission of the same logical
     * action fails the insert and takes the transaction with it.
     *
     * **IT IS HASHED, NOT STORED.** A caller's string written verbatim
     * into a 255-character column would be an app-content channel into a
     * stream whose premise is that no app content enters it (D15) — an
     * app could pass a request value straight in, and a future consumer
     * of this schema would discover it had one. The digest is over the
     * VOCABULARY, the ACTION and the key together, which also removes
     * the global collision domain the previous revision had: two
     * unrelated vocabularies choosing the same natural key used to
     * suppress each other's events silently, because one flat string
     * space held every app's keys at once.
     *
     * Omitting it defaults to the event's own id, which dedupes nothing
     * — that is the honest reading of "this action has no identity", and
     * such a caller gets no duplicate protection. A caller that CAN name
     * its action passes a key.
     *
     * @throws LogicException outside a transaction, or on a row the stream refuses
     */
    public function record(
        AppAction $action,
        AppActionActor $actor,
        AppActionReason $reason,
        ?string $naturalKey = null,
    ): AppActionEvent {
        // No `id` is passed and `id` is not fillable on either model:
        // HasUuids generates both, which is what makes "a
        // package-generated event id" true of this path rather than a
        // hope about what the caller supplied.
        //
        // The event's own `creating` hook re-checks the shape of what is
        // written here. That is defence in depth, not a second gate, and
        // there is deliberately no third copy of those checks in this
        // method to drift from either of them.
        $event = AppActionEvent::query()->create([
            'action' => $action->value,
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
        // the same logical action is never recorded twice, and a caller
        // that tried is told rather than left holding one of two.
        AppActionOutboxEntry::query()->create([
            'event_id' => $event->id,
            'dedup_key' => self::dedupKeyFor($action, $naturalKey ?? $event->id),
        ]);

        return $event;
    }

    /**
     * The ledger key: sha256 over a LENGTH-DELIMITED encoding of the
     * vocabulary, the action and the caller's natural key.
     *
     * **PUBLIC so that a caller's keying can be PINNED rather than
     * restated.** A test asserting only that the stored key is 64 hex
     * characters cannot tell a key derived from the caller's natural key
     * from the default derived from the event id — which is exactly the
     * hole that opened when the door's mint-keying assertion was
     * weakened: deleting `naturalKey:` from `ConsoleEnter` still yielded
     * a 64-hex digest and the whole suite stayed green. A test that
     * recomputes the expected key from the MINT, through this method,
     * reds on that deletion. It is a pure function of its arguments and
     * touches nothing.
     *   Pinned by `tests/ConsoleEnterAuditTest.php` — "keys a successful
     *   entry's ledger row to the mint, so dropping the key falls back
     *   to the event id".
     *
     * Length-delimited for the reason
     * {@see DelegatedActor::identityHash()}
     * and {@see AssertionBurn::mintHash()}
     * are: without the lengths, one field's suffix and the next one's
     * prefix concatenate alike, so two different actions could hash to
     * one key — and a collision here does not merely mis-file a row, it
     * SUPPRESSES an event, because the second insert is refused as a
     * duplicate. A boundary that can be shifted is not a boundary.
     */
    public static function dedupKeyFor(AppAction $action, string $naturalKey): string
    {
        $vocabulary = $action::class;
        $name = (string) $action->value;

        return hash('sha256', implode(':', [
            strlen($vocabulary), $vocabulary,
            strlen($name), $name,
            strlen($naturalKey), $naturalKey,
        ]));
    }
}
