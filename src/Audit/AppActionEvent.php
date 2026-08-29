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
 * of the three principals D17 names.
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
 * **THE ROW GUARDS ITSELF, and that is where the schema's promises are
 * actually kept.** {@see AppActionRecorder} is the only path this
 * package offers, but it is not a gate PHP can close: `AppActionEvent`
 * is an ordinary Eloquent model, and an app that calls
 * `AppActionEvent::query()->create([...])` reaches the same table. So
 * the invariants are enforced HERE, on `creating`, where they hold for
 * every path that goes through the model rather than only for callers
 * who chose the front door. {@see assertWellFormed()} lists them; each
 * is a criterion the stream would otherwise be claiming by convention:
 *
 *  - the action is a case of a real compile-time {@see AppAction}
 *    vocabulary, and its backing value is a bounded identifier;
 *  - the actor type is a member of {@see AppActorType}, and a delegated
 *    actor is named by its TYPE-QUALIFIED identity;
 *  - `on_behalf_of` is absent unless the actor is delegated;
 *  - there is an open transaction.
 *
 *   Pinned by `tests/AppActionAuditTest.php` — "refuses a direct model
 *   write that carries runtime prose as its action", "refuses a direct
 *   model write whose action is not a case of the vocabulary it names",
 *   "refuses a direct model write that names a delegated actor by a bare
 *   id" and "refuses a direct model write that fabricates an agency for
 *   a local user"; and by `tests/RecorderTransactionGuardTest.php` —
 *   "refuses a direct model write made outside a transaction", which
 *   lives there because RefreshDatabase wraps every test it touches in a
 *   transaction and would make the case under test unreachable.
 *
 * **THE ONE INVARIANT THIS HOOK CANNOT KEEP, named rather than left to
 * be found: the ledger row.** "Exactly one event per action" is a unique
 * index on {@see AppActionOutboxEntry}, and a row cannot write its own
 * ledger entry from `creating` — the event id it would reference is not
 * inserted yet. A direct model write that satisfies everything above
 * therefore persists an event with NO ledger row and no dedup
 * protection. That is the residue of not having a closable gate, it is
 * the reason {@see AppActionRecorder} is described as the only
 * VALIDATED-AND-LEDGERED path rather than the only path, and this
 * package never takes it.
 *
 * **NO FREE TEXT (D15).** The credential stream carries a bounded `note`;
 * this one carries nothing of the kind, and there is deliberately no
 * column an app could put prose in. `action` is refused above unless it
 * is a bounded identifier from a declared vocabulary; `reason` is a
 * closed package enum ({@see AppActionReason}).
 *
 * THE ONE STRING THAT IS NOT AN IDENTIFIER, named rather than left to be
 * found: `on_behalf_of`. D4 requires the agency a delegated operator
 * acts for, and it is CALLER-SUPPLIED — this model constrains only that
 * it accompanies a delegated actor and nothing else. On the path this
 * package takes it is the issuer-minted claim
 * {@see AssertionVerifier} bounded
 * and rejected for control characters, carried through
 * {@see AppActionActor::fromActingPrincipal()}; a caller that builds an
 * actor by hand owns the truth of what it passes.
 * **Escape it at every sink.**
 *
 * **APPEND-ONLY, in three layers that cover different paths.** The model
 * throws on `updating` and `deleting`, which covers INSTANCE operations
 * ($row->update(), $row->delete()). {@see AppendOnlyBuilder} refuses the
 * ten enumerated BULK spellings — `update`, `delete`, `truncate` and the
 * rest — which fire no model events at all and would otherwise compile
 * straight to SQL. Database triggers, on the three drivers this package
 * writes them for, abort raw row-level UPDATE and DELETE so a
 * `DB::table(...)` write cannot rewrite history either.
 *
 * **THE RESIDUE, stated honestly rather than claimed away.** This is not
 * an absolute, and each layer's edge is a real one. Raw `TRUNCATE TABLE`
 * SQL is DDL and no row trigger sees it. A raw INSERT — `DB::table(...)`
 * or `AppActionEvent::query()->insert([...])`, which fires no model
 * events — skips `assertWellFormed()` entirely; the triggers guard
 * UPDATE and DELETE, not INSERT. A driver this package writes no
 * triggers for (sqlsrv) has the model and builder layers and nothing
 * beneath them. Privileged schema access can DROP the triggers, and
 * direct file access to a sqlite database rewrites anything. TRUNCATE
 * and DROP enforcement, where an operator wants it, is a
 * DATABASE-PRIVILEGE matter — revoke DDL from the app's connection — not
 * something a model guard can give. Append-only here is by construction,
 * not cryptographic: a compromised instance can tamper with its own
 * history.
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
     * @var list<string>
     */
    protected $fillable = [
        'id',
        'action',
        'action_vocabulary',
        'reason',
        'actor_type',
        'actor_ref',
        'on_behalf_of',
        'occurred_at',
    ];

    /**
     * Refuse a row that would break one of the stream's own invariants,
     * whoever is writing it.
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

        // The type qualifier, enforced at the row rather than only at
        // the factory that usually builds it. `bfc_delegated_actors` is
        // an ordinary auto-increment table in the same id space `users`
        // occupies, so a bare `7` here would read as user 7.
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
