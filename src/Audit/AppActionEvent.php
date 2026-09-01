<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Audit;

use ArtisanBuild\BuiltForCloud\Console\AssertionVerifier;
use ArtisanBuild\BuiltForCloud\Console\DelegatedActor;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\MetadataShape;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use LogicException;

/**
 * One row in the instance-side, append-only APP-ACTION audit stream
 * (Console PRD D17): who did what, in this deployment, attributed to one
 * of the four principals D17 names.
 *
 * **A SEPARATE STREAM, NOT AN EXTENSION.** The shipped
 * {@see CredentialAuditEvent} stream is credential-work only — its event
 * vocabulary, its actor vocabulary and its columns all describe
 * credential lifecycle — and D17 says plainly that it is NOT extended.
 * This model has its own table, its own ledger and its own emission
 * point, and this package adds no column to, and writes no row to, the
 * credential stream on any app-action path.
 *   Pinned by `tests/AppActionAuditTest.php` — "leaves the credential
 *   stream's shape untouched" and "writes nothing to the credential
 *   stream when an app action is recorded".
 *
 * **THE ENFORCED BOUNDARY IS {@see AppActionRecorder}, NOT THIS MODEL,
 * and reading it the other way round is the mistake this docblock spent
 * three review rounds making.** Every guarantee this stream makes — a
 * bounded action from a compile-time vocabulary, a type-qualified actor,
 * an agency only on a delegated actor, a package-generated id, a
 * transactional emission, one event per caller-identified action, a
 * digest dedup key — is a property of **what the package writes through
 * the recorder**. None
 * of them is a property of what a row in this table can contain.
 * "Transactional" has a connection precondition: this model and the
 * recorder use the default database connection, so the event shares the
 * action's transaction only when the action uses that same connection.
 * {@see AppActionRecorder} states the mismatch behavior and the
 * consumer's responsibility in full.
 *
 * **THE RESIDUE, and it is the load-bearing sentence: an app holding
 * this model can write its own database directly, and the package
 * neither prevents nor detects that.** `AppActionEvent` is an ordinary
 * public Eloquent model in the consuming app's own schema. `insert()`,
 * `saveQuietly()`, `Model::withoutEvents()`, `toBase()`, a raw
 * `DB::table(...)` write and any Eloquent builder spelling that forwards
 * through `Builder::__call()` all reach the table without firing this
 * model's events. That was always true; three revisions of this
 * paragraph denied it, each time by enumerating one more spelling, and
 * each round the reviewer found another. The enumeration cannot
 * terminate, so the claim is narrowed instead: **what the package
 * guarantees is what the package writes.**
 *
 * **{@see assertWellFormed()} IS DEFENCE IN DEPTH, NOT A BOUNDARY.** It
 * runs on `creating`, so it catches the ordinary mistake — a consuming
 * app reaching for `create()` because the recorder was not obvious — and
 * it is worth having for exactly that. It refuses an action that is not
 * a bounded-identifier case of a real {@see AppAction} vocabulary, an
 * actor type outside {@see AppActorType}, a delegated actor whose ref
 * carries no type qualifier, an `on_behalf_of` on any other actor type,
 * and a write with no default-connection transaction open. **No claim in
 * this package depends on that list being complete**, and it demonstrably
 * is not: it validates the SHAPE of what it is handed, so a ref of
 * `bfc-console:not-an-id` satisfies the qualifier check, and any write
 * that does not fire `creating` skips it entirely.
 *   Pinned by `tests/AppActionAuditTest.php` — "refuses a direct model
 *   write that carries runtime prose as its action", "refuses a direct
 *   model write whose action is not a case of the vocabulary it names",
 *   "refuses a direct model write that names a delegated actor by a bare
 *   id" and "refuses a direct model write that fabricates an agency for
 *   a local user".
 *
 *   Pinned by `tests/RecorderTransactionGuardTest.php` — "refuses a
 *   direct model write made outside a transaction", which lives there
 *   because RefreshDatabase wraps every test it touches in a transaction
 *   and would make the case under test unreachable.
 *
 * A further gap in the same direction, named because it is the one a
 * reader would otherwise assume closed: a write that satisfies every
 * check above still gets **no ledger row**, because a row cannot write
 * its own ledger entry from `creating` — the event id it would reference
 * is not inserted yet. One event per caller-identified action is
 * therefore a property of the recorder and of nothing else — and, on the
 * recorder itself, only of calls that supply a natural key.
 * {@see AppActionRecorder::record()} states the condition in full.
 *   Pinned by `tests/AppActionAuditTest.php` — "persists a well-formed
 *   direct model write with no ledger row, which is the residue the
 *   recorder names".
 *
 * **NO FREE TEXT (D15) — in what the recorder writes.** The credential
 * stream carries a bounded `note`; this schema designates no column of
 * that kind at all, and THAT absence is structural. Recorder emissions
 * are bounded enums and identifiers throughout, except the delegated
 * agency display string below: `action` is a compile-time enum case on
 * that path, `reason` is a closed package enum
 * ({@see AppActionReason}). The TABLE is not what holds that line — its
 * string columns can physically take prose through the direct writes
 * named above.
 *
 * THE ONE STRING THAT IS NOT AN IDENTIFIER: `on_behalf_of`. D4 requires
 * the agency a delegated operator acts for, and it is **caller-supplied
 * on every path, this package's included**. {@see AppActionRecorder}
 * can carry an agency only through a delegated {@see AppActionActor} —
 * the private constructor and its factories are what enforce that — and
 * the `creating` hook also refuses other combinations when it runs.
 * **The schema itself does not constrain the relationship**: a raw or
 * event-free insert can store `actor_type=local_user` beside a non-null
 * `on_behalf_of`. What the value SAYS is the caller's to be right about
 * on every path. The package has two paths and both are legitimate:
 * `POST /bfc/console/enter` calls {@see AppActionActor::delegated()}
 * directly with the claims of the session it has just opened, because
 * the request-scoped acting principal was resolved before that session
 * existed; every other emission goes through
 * {@see AppActionActor::fromActingPrincipal()}. On both, the value
 * originates as an issuer-minted claim that
 * {@see AssertionVerifier} bounded to 120 characters and rejected for
 * control characters. A consuming app calling the factory itself
 * supplies whatever it likes and owns the truth of it.
 * **Escape it at every sink.**
 *
 * **APPEND-ONLY, in three layers, and the honest summary is "hard to do
 * by accident".** The model throws on `updating` and `deleting`, which
 * covers INSTANCE operations (`$row->update()`, `$row->delete()`).
 * {@see AppendOnlyBuilder} refuses an enumerated set of BULK spellings,
 * which fire no model events and would otherwise compile straight to
 * SQL. Database triggers, on the three drivers this package writes them
 * for, abort raw row-level UPDATE and DELETE.
 *
 * **AND NONE OF THE THREE IS A BOUNDARY.** Raw `TRUNCATE TABLE` is DDL
 * and no row trigger sees it. A raw INSERT — `DB::table(...)`, or any
 * builder insert spelling — fires no model events, and the triggers
 * guard UPDATE and DELETE, not INSERT. `deleteQuietly()` and
 * `Model::withoutEvents()` mute the model layer outright. The builder's
 * list is a fixed enumeration of names, and a spelling not on it
 * forwards straight through. A driver this package writes no triggers
 * for (sqlsrv) has the first two layers and nothing beneath them.
 * Privileged schema access can DROP the triggers; direct file access to
 * a sqlite database rewrites anything. TRUNCATE and DROP enforcement,
 * where an operator wants it, is a DATABASE-PRIVILEGE matter — revoke
 * DDL from the app's connection — not something a model guard can give.
 * Append-only here is a strong convention with three tripwires under it,
 * not a cryptographic property: an app, or a compromised instance, can
 * tamper with its own history.
 *   Pinned by `tests/AppActionAuditTest.php` — "rejects update and
 *   delete on an app-action event at the model layer", "refuses every
 *   enumerated bulk mutation on the app-action stream, on both models",
 *   "rejects truncate on the app-action stream, on both the static and
 *   the query-builder paths" and "rejects raw update and delete on the
 *   app-action table at the database layer on sqlite".
 *
 * **RETENTION IS DECLARED, AND THE DECLARATION IS THAT NOTHING PRUNES
 * IT.** App-action events are attribution history and this package never
 * deletes one — the same decision already taken for the shadow actor
 * row, and for the same reason: an attribution trail that quietly
 * shortens is one an operator cannot rely on. There is no prune command,
 * no scheduled sweep and no retention setting. The storage cost is
 * therefore UNBOUNDED and grows with the app's activity forever; an
 * operator who needs that bounded is choosing a different retention
 * policy than this stream declares, and would have to implement it
 * outside the package.
 *   Pinned by `tests/AppActionAuditTest.php` — "finds no enumerated
 *   deletion spelling against the app-action stream anywhere in src" and
 *   "names every enumerated deletion spelling when the walk meets one".
 *
 * @property string $id
 * @property string $action
 * @property string $action_vocabulary
 * @property AppActionReason $reason
 * @property AppActorType $actor_type
 * @property string $actor_ref
 * @property string|null $on_behalf_of
 * @property CarbonInterface $occurred_at
 * @property CarbonInterface|null $created_at
 */
final class AppActionEvent extends Model
{
    use HasUuids;

    public const UPDATED_AT = null;

    /**
     * Named for the stream rather than for the Console: the actions it
     * records are the APP's, and the Console is only the first emitter.
     */
    protected $table = 'bfc_app_action_events';

    public $incrementing = false;

    protected $keyType = 'string';

    /**
     * **`id` IS DELIBERATELY NOT FILLABLE.** D17 wants a package-generated
     * event id, and `HasUuids` only generates one when the attribute is
     * empty — so while `id` was fillable, a caller could supply its own
     * and the "generated by the package" sentence was false for exactly
     * the path that sentence was about. Off the fillable list, mass
     * assignment cannot set it and {@see HasUuids} always does. A raw
     * `insert()` or `forceFill()` still can, which is the same residue
     * the class docblock names; what changed is that the ordinary path
     * no longer contradicts the claim.
     *
     * @var list<string>
     */
    protected $fillable = [
        'action',
        'action_vocabulary',
        'reason',
        'actor_type',
        'actor_ref',
        'on_behalf_of',
        'occurred_at',
    ];

    /**
     * Refuse a row that would break one of the stream's own invariants —
     * **defence in depth, on the writes that fire this model's
     * `creating` event, and not a boundary.** The class docblock says
     * what that does not cover and why no claim rests on it.
     *
     * It takes the RAW ATTRIBUTE ARRAY rather than a model so that the
     * checks read against what is about to be stored. Two of them are
     * already made for us before this runs, by the enum casts:
     * `actor_type` and `reason` are refused with a `ValueError` at
     * assignment time if they name a member that does not exist, so what
     * is left here is their PRESENCE and how they relate to the other
     * columns.
     *
     * Every refusal is total. Nothing is trimmed, defaulted or coerced:
     * a row the contract forbids does not become a row the contract
     * permits by being edited on its way in, and an audit record edited
     * by the thing recording it is not a record.
     *
     * @param  array<string, mixed>  $attributes
     *
     * @throws LogicException
     */
    public static function assertWellFormed(array $attributes): void
    {
        if (DB::transactionLevel() === 0) {
            throw new LogicException(
                'App-action events record inside the action\'s own transaction, never outside one.',
            );
        }

        $vocabulary = $attributes['action_vocabulary'] ?? null;

        if (! is_string($vocabulary) || ! enum_exists($vocabulary) || ! is_a($vocabulary, AppAction::class, true)) {
            throw new LogicException(
                'An app action names the compile-time vocabulary its case came from; '
                .'this row names something that is not an '.AppAction::class.'.',
            );
        }

        $action = $attributes['action'] ?? null;

        if (! is_string($action) || ! MetadataShape::isToken($action)) {
            throw new LogicException(
                'An app action is named by a bounded identifier from a compile-time vocabulary; '
                .$vocabulary.' backs a case with something else.',
            );
        }

        // Compared case by case rather than through `tryFrom()`, which
        // takes an int on an int-backed enum and would fatal here rather
        // than refuse. The identifier check above has already excluded
        // an int-backed case; this one says the name is genuinely IN the
        // vocabulary it claims, not merely identifier-shaped.
        $declared = array_map(
            static fn (AppAction $case): int|string => $case->value,
            $vocabulary::cases(),
        );

        if (! in_array($action, $declared, true)) {
            throw new LogicException(
                'An app action is a case of the vocabulary it names; '.$action.' is not one of '.$vocabulary.'\'s.',
            );
        }

        if (! AppActionReason::tryFrom((string) ($attributes['reason'] ?? '')) instanceof AppActionReason) {
            throw new LogicException('An app-action event carries a reason from the closed package vocabulary.');
        }

        $actorType = AppActorType::tryFrom((string) ($attributes['actor_type'] ?? ''));
        $actorRef = $attributes['actor_ref'] ?? null;

        if (! $actorType instanceof AppActorType || ! is_string($actorRef) || $actorRef === '') {
            throw new LogicException(
                'An app-action event names the principal that performed it; there is no unattributed app action.',
            );
        }

        // The type qualifier. `bfc_delegated_actors` is an ordinary
        // auto-increment table in the same id space `users` occupies, so
        // a bare `7` here would read as user 7. This checks the PREFIX
        // and nothing more — `bfc-console:not-an-id` passes it — because
        // the model has no way to know which actor rows exist and a
        // lookup here would put a query in a validation hook. What makes
        // the ref a real identity is that the recorder took it from
        // DelegatedActor::getAuthIdentifier(); this only catches the
        // bare-integer mistake.
        if ($actorType === AppActorType::DelegatedActor
            && ! str_starts_with($actorRef, DelegatedActor::IDENTIFIER_PREFIX)) {
            throw new LogicException(
                'A delegated actor is named by its type-qualified identity ('
                .DelegatedActor::IDENTIFIER_PREFIX.'{id}), never the bare key.',
            );
        }

        $onBehalfOf = $attributes['on_behalf_of'] ?? null;

        if ($onBehalfOf === null) {
            return;
        }

        // D4's agency belongs to a delegated session and to nothing
        // else: a local user acts for the deployment they log in to, and
        // a credential acts for itself. A row that put an agency on
        // either would be attributing an action to a party that never
        // authorised it.
        if ($actorType !== AppActorType::DelegatedActor) {
            throw new LogicException(
                'Only a delegated actor acts on behalf of an agency; a '.$actorType->value.' event carries none.',
            );
        }

        if (! is_string($onBehalfOf) || $onBehalfOf === '') {
            throw new LogicException('An agency is a non-empty string, or it is absent entirely.');
        }
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'reason' => AppActionReason::class,
            'actor_type' => AppActorType::class,
            'occurred_at' => 'datetime',
        ];
    }

    protected static function booted(): void
    {
        self::creating(function (AppActionEvent $event): void {
            self::assertWellFormed($event->getAttributes());
        });

        self::updating(function (): never {
            throw new LogicException('The app-action audit stream is append-only: rows are never updated.');
        });

        self::deleting(function (): never {
            throw new LogicException('The app-action audit stream is append-only: rows are never deleted.');
        });
    }

    /**
     * @param  Builder  $query
     */
    public function newEloquentBuilder($query): AppActionEventBuilder
    {
        return new AppActionEventBuilder($query);
    }
}
