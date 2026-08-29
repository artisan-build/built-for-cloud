<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Audit;

use ArtisanBuild\BuiltForCloud\Console\AssertionBurn;
use ArtisanBuild\BuiltForCloud\Console\DelegatedActor;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use Illuminate\Support\Str;
use LogicException;

/**
 * The only VALIDATED-AND-LEDGERED path into the app-action audit stream
 * (Console PRD D17): one call appends the event row AND its dedup ledger
 * row, in the caller's own transaction.
 *
 * **IT IS NOT "THE SINGLE EMISSION POINT", AND AN EARLIER REVISION OF
 * THIS SENTENCE SAID IT WAS.** {@see AppActionEvent} is an ordinary
 * Eloquent model; an app can call `AppActionEvent::query()->create([...])`
 * and reach the same table without ever touching this class, and PHP
 * offers no way to close that which is not a mutable flag some other
 * object sets — which is a by-convention gate wearing by-construction
 * clothes, and this codebase has already rejected that trade once.
 *
 * So the guarantee was moved to where it can actually hold: **the row
 * validates itself on `creating`**, for every path that goes through the
 * model. What is left over, exactly, and it is the whole of the
 * difference between this class and a direct write:
 *
 *  - a direct write gets NO DEDUP LEDGER ROW, so "exactly one event per
 *    action" does not apply to it — the ledger row cannot be written
 *    from `creating`, because the event id it references is not
 *    inserted yet;
 *  - a direct write chooses its own `action_vocabulary` string, so the
 *    compile-time enum is a check on what that string NAMES rather than
 *    on the caller having had an enum case in hand;
 *  - a raw `DB::table(...)` or `->insert([...])` write fires no model
 *    events and skips the validation entirely.
 *
 * The package never takes any of those. An app that does is writing its
 * own rows into its own database, which no package can prevent and this
 * one does not claim to.
 *
 * **THE STREAM IS TRANSACTIONAL OR IT IS FICTION** — the same ruling
 * {@see LifecycleEventRecorder} already carries, and for the same
 * reason. An action that rolls back takes its event and its ledger row
 * with it, so nothing is ever recorded about something that did not
 * happen; an event written outside the action's transaction is a record
 * that can outlive the thing it records. The check lives on the MODEL
 * rather than here, so it holds for a direct write too, and this class
 * opens no transaction of its own: one it opened would commit
 * independently of the caller's, which is precisely the failure the
 * requirement exists to prevent.
 *   Pinned by `tests/RecorderTransactionGuardTest.php` — "refuses to
 *   record an app action outside a database transaction"; and
 *   `tests/AppActionAuditTest.php` — "leaves neither the event nor its
 *   ledger row behind when the action rolls back" and "refuses a direct
 *   model write made outside a transaction".
 *
 * **THE ACTION IS AN ENUM CASE, AND ON THIS PATH THE TYPE IS THE
 * ENFORCEMENT.** The parameter is typed {@see AppAction}, which extends
 * `BackedEnum`, so a string cannot be passed at all — a `list<string>`
 * of permitted names would have been convention, and an app could have
 * supplied it from `Tag::pluck('slug')`. That is a statement about THIS
 * method's signature; the model's own refusal is what covers a direct
 * write, and it checks the stored value rather than the caller's type.
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
        // The event refuses itself if any of this is wrong — including
        // the transaction — so there is deliberately no second copy of
        // those checks here to drift from them.
        $event = AppActionEvent::query()->create([
            'id' => (string) Str::uuid(),
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
            'id' => (string) Str::uuid(),
            'event_id' => $event->id,
            'dedup_key' => self::dedupKey($action, $naturalKey ?? $event->id),
        ]);

        return $event;
    }

    /**
     * The ledger key: sha256 over a LENGTH-DELIMITED encoding of the
     * vocabulary, the action and the caller's natural key.
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
    private static function dedupKey(AppAction $action, string $naturalKey): string
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
