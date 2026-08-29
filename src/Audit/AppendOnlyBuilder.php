<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Audit;

use ArtisanBuild\BuiltForCloud\CredentialAuditEventBuilder;
use Illuminate\Contracts\Database\Query\Expression;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use LogicException;

/**
 * The Eloquent builder both halves of the app-action stream use: it
 * refuses **every enumerated spelling that could change or remove a row,
 * or create one without the row validating itself**, on the static path
 * (`AppActionEvent::truncate()` resolves through here) and the query path
 * (`AppActionEvent::query()->update([...])`) alike.
 *
 * WHY IT EXISTS AT ALL, given the model already throws on `updating` and
 * `deleting`. Model events fire on INSTANCE operations only. A BULK
 * `->update([...])` or `->delete()` compiles straight to SQL and fires
 * nothing, so without these overrides the model-layer guarantee covered
 * `$row->delete()` and not `Model::query()->delete()` — and the
 * difference matters most on a driver this package ships no triggers for
 * (sqlsrv), where the model layer is the *only* enforcement there is.
 * `truncate()` is the sharpest case: it is DDL on mysql, where the row
 * triggers never fire at all.
 *   Pinned by `tests/AppActionAuditTest.php` — "refuses every enumerated
 *   bulk mutation on the app-action stream, on both models" and "pins the
 *   exact set of operations the append-only builder refuses".
 *
 * **IT IS DEFENCE IN DEPTH, NOT A BOUNDARY, and that framing is the
 * whole of what changed in review round 2.** {@see REFUSED} is a FIXED
 * LIST OF METHOD NAMES. `Illuminate\Database\Eloquent\Builder`
 * forwards everything it does not declare to the query builder through
 * `__call()`, so a spelling not on this list reaches the table
 * untouched — and three consecutive review rounds each found spellings
 * the previous round had missed (`createQuietly`, then `deleteQuietly`,
 * then `insertOrIgnoreReturning`, `insertOrIgnoreUsing` and
 * `updateFrom`). An enumeration of a framework's surface does not
 * terminate.
 *
 * So **no claim in this package depends on this list being complete.**
 * The stream's guarantees are properties of what
 * {@see AppActionRecorder} writes; this class exists to make the
 * ordinary mistake loud, which is worth doing and is all it does. A test
 * pins the class's declared surface against {@see REFUSED} so that
 * removing an override is a deliberate diff rather than a quiet one —
 * that pin is about drift in THIS list, not about coverage of Laravel's.
 *
 * **WHAT IT DOES NOT REACH, named because an unlisted gap reads as a
 * covered one:**
 *
 *  - **`insert()` ITSELF, and it is the one deliberate hole.**
 *    `Model::performInsert()` calls `$query->insert($attributes)` for a
 *    non-incrementing key, which is exactly what both these models are,
 *    so refusing `insert()` would refuse the package's own writes. It
 *    is therefore the single mutating spelling on this class's surface
 *    that is NOT refused. An insert made through it directly fires no
 *    model events and skips {@see AppActionEvent}'s row validation —
 *    the same residue as a raw `DB::table(...)->insert(...)`. Every
 *    OTHER insert spelling is refused, `insertOrIgnore()` most of all:
 *    it would swallow the unique-index violation that "exactly one
 *    event per action" rests on.
 *  - **The MODEL's own quiet family.** `saveQuietly()`,
 *    `deleteQuietly()` and `forceDeleteQuietly()` are instance methods
 *    on the model, not on this builder, and they run inside
 *    `Model::withoutEvents()` — so they mute the append-only guards
 *    exactly as `createQuietly()` would have. They are caught by the
 *    database triggers on the three drivers this package writes them
 *    for, and by nothing on a driver it does not; `deleteQuietly` is
 *    one of the spellings `tests/AppActionRetentionScan.php` enumerates
 *    for that reason.
 *  - **Anything not on the list**, which is the residue that matters
 *    and cannot be closed by adding to it. {@see REFUSED} is what this
 *    class refuses DIRECTLY. A framework helper composed out of these —
 *    `incrementOrCreate()`, say — ends at whichever of them it calls and
 *    is refused there, but that is a property of the helper, not a claim
 *    this class makes about helpers it has never heard of. A NEW mutator
 *    arriving in a future Laravel is simply inherited, unrefused, and
 *    unnoticed: the surface pin cannot see it, because the surface did
 *    not change. Reviewing a framework upgrade is the control, and it is
 *    a human one.
 *  - **`toBase()`**, which hands back the query builder these overrides
 *    are not on. Anything that goes around the Eloquent builder is a raw
 *    write, and raw writes are the enforcement boundary the model states.
 *  - **Reflection, and a differently named future mutator.** This is a
 *    fixed list, like every other tripwire in this package.
 *
 * The REFUSALS live here once, in this abstract base, and each model
 * gets a two-line subclass that binds it to that model
 * ({@see AppActionEventBuilder}, {@see AppActionLedgerBuilder}). The
 * credential stream ships {@see CredentialAuditEventBuilder} per model
 * with its own body; sharing the body here means the two halves of one
 * stream cannot drift apart on which operations they refuse, which is
 * the property that matters when the ledger's whole job is to outlive
 * attempts to remove it. The subclasses exist only so each builder is
 * typed for its own model; they add and override nothing.
 *
 * @template TModel of Model
 *
 * @extends Builder<TModel>
 */
abstract class AppendOnlyBuilder extends Builder
{
    /**
     * Every operation this builder refuses, sorted. It is the
     * enumeration the guarantee rests on, and a test pins the class's
     * own declared surface against it.
     *
     * Three families, and each is here for a different bypass:
     *
     *  - **bulk writes** (`update`, `delete`, `truncate`, the
     *    increment/decrement pairs, `touch`, `upsert`,
     *    `updateOrInsert`) compile straight to SQL and fire no model
     *    events, so the model's own `updating`/`deleting` guards never
     *    see them;
     *  - **quiet creates** (`createQuietly`, `forceCreateQuietly`) run
     *    inside `Model::withoutEvents()`, which mutes `creating` and
     *    with it {@see AppActionEvent::assertWellFormed()} — a create
     *    that skips the row's own validation is exactly the write this
     *    stream must not accept;
     *  - **event-free inserts** (`insertOrIgnore`,
     *    `insertOrIgnoreReturning`, `insertOrIgnoreUsing`,
     *    `insertGetId`, `insertUsing`, and the three `fillAndInsert*`
     *    helpers that forward to them) fire no model events either. The
     *    `insertOrIgnore` family is the sharpest: it would SWALLOW the
     *    unique-index violation that one event per caller-identified
     *    action rests on. `updateFrom` is PostgreSQL's `UPDATE ... FROM` and
     *    belongs to the first family; it sits with these because, like
     *    them, it is reached ONLY through `__call()` forwarding — which
     *    is how all three arrived on this list, after a reviewer wrote
     *    them and watched a forged row persist.
     *
     * @var list<string>
     */
    public const array REFUSED = [
        'createQuietly',
        'decrement',
        'decrementEach',
        'delete',
        'fillAndInsert',
        'fillAndInsertGetId',
        'fillAndInsertOrIgnore',
        'forceCreateQuietly',
        'forceDelete',
        'increment',
        'incrementEach',
        'insertGetId',
        'insertOrIgnore',
        'insertOrIgnoreReturning',
        'insertOrIgnoreUsing',
        'insertUsing',
        'touch',
        'truncate',
        'update',
        'updateFrom',
        'updateOrInsert',
        'upsert',
    ];

    /**
     * @param  array<string, mixed>  $attributes
     */
    public function createQuietly(array $attributes = []): never
    {
        $this->refuse('created without the row validating itself');
    }

    /**
     * @param  array<string, mixed>  $attributes
     */
    public function forceCreateQuietly(array $attributes = []): never
    {
        $this->refuse('created without the row validating itself');
    }

    /**
     * @param  array<string, mixed>  $values
     */
    public function update(array $values): never
    {
        $this->refuse('updated');
    }

    /**
     * @param  array<int, array<string, mixed>>  $values
     * @param  array<int, string>|string  $uniqueBy
     * @param  array<int, string>|null  $update
     */
    public function upsert(array $values, $uniqueBy, $update = null): never
    {
        $this->refuse('updated');
    }

    /**
     * @param  array<string, mixed>  $attributes
     * @param  array<string, mixed>  $values
     */
    public function updateOrInsert(array $attributes, array $values = []): never
    {
        $this->refuse('updated');
    }

    /**
     * @param  array<int, string>|string|null  $column
     */
    public function touch($column = null): never
    {
        $this->refuse('updated');
    }

    /**
     * @param  Expression|string  $column
     * @param  float|int  $amount
     * @param  array<string, mixed>  $extra
     */
    public function increment($column, $amount = 1, array $extra = []): never
    {
        $this->refuse('updated');
    }

    /**
     * @param  Expression|string  $column
     * @param  float|int  $amount
     * @param  array<string, mixed>  $extra
     */
    public function decrement($column, $amount = 1, array $extra = []): never
    {
        $this->refuse('updated');
    }

    /**
     * @param  array<string, float|int|numeric-string>  $columns
     * @param  array<string, mixed>  $extra
     */
    public function incrementEach(array $columns, array $extra = []): never
    {
        $this->refuse('updated');
    }

    /**
     * @param  array<string, float|int|numeric-string>  $columns
     * @param  array<string, mixed>  $extra
     */
    public function decrementEach(array $columns, array $extra = []): never
    {
        $this->refuse('updated');
    }

    public function delete(): never
    {
        $this->refuse('deleted');
    }

    public function forceDelete(): never
    {
        $this->refuse('deleted');
    }

    /**
     * @param  array<int, array<string, mixed>>  $values
     */
    public function insertOrIgnore(array $values): never
    {
        $this->refuse('inserted by a path that fires no model events');
    }

    /**
     * @param  array<string, mixed>  $values
     */
    public function insertGetId(array $values, ?string $sequence = null): never
    {
        $this->refuse('inserted by a path that fires no model events');
    }

    /**
     * @param  array<int, array<string, mixed>>  $values
     * @param  non-empty-array<non-empty-string>  $returning
     * @param  non-empty-array<non-empty-string>|string|null  $uniqueBy
     */
    public function insertOrIgnoreReturning(array $values, array $returning = ['*'], array|string|null $uniqueBy = null): never
    {
        $this->refuse('inserted by a path that fires no model events');
    }

    /**
     * @param  array<int, string>  $columns
     */
    public function insertOrIgnoreUsing(array $columns, mixed $query): never
    {
        $this->refuse('inserted by a path that fires no model events');
    }

    /**
     * @param  array<int, string>  $columns
     */
    public function insertUsing(array $columns, mixed $query): never
    {
        $this->refuse('inserted by a path that fires no model events');
    }

    /**
     * PostgreSQL's `UPDATE ... FROM`, reached only through `__call()`
     * forwarding.
     *
     * @param  array<string, mixed>  $values
     */
    public function updateFrom(array $values): never
    {
        $this->refuse('updated');
    }

    /**
     * @param  array<int, array<string, mixed>>  $values
     */
    public function fillAndInsert(array $values): never
    {
        $this->refuse('inserted by a path that fires no model events');
    }

    /**
     * @param  array<int, array<string, mixed>>  $values
     */
    public function fillAndInsertOrIgnore(array $values): never
    {
        $this->refuse('inserted by a path that fires no model events');
    }

    /**
     * @param  array<string, mixed>  $values
     */
    public function fillAndInsertGetId(array $values): never
    {
        $this->refuse('inserted by a path that fires no model events');
    }

    public function truncate(): never
    {
        // Worded differently on purpose: TRUNCATE is not a row operation
        // and no trigger this package ships sees it, so the message says
        // what the model layer is standing in for.
        throw new LogicException(
            'The '.$this->getModel()->getTable().' stream is append-only: the table is never truncated.',
        );
    }

    private function refuse(string $operation): never
    {
        throw new LogicException(
            'The '.$this->getModel()->getTable().' stream is append-only: rows are never '.$operation.'.',
        );
    }
}
