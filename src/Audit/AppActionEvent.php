<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Audit;

use ArtisanBuild\BuiltForCloud\Console\AssertionVerifier;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Query\Builder;
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
 * This model has its own table, its own outbox and its own emission
 * point, and this package adds no column to, and writes no row to, the
 * credential stream on any app-action path.
 *   Pinned by `tests/AppActionAuditTest.php` — "leaves the credential
 *   stream's shape untouched" and "writes nothing to the credential
 *   stream when an app action is recorded".
 *
 * **NO FREE TEXT (D15).** The credential stream carries a bounded `note`;
 * this one carries nothing of the kind, and there is deliberately no
 * column an app could put prose in. `action` is the backing value of a
 * case from an app-declared compile-time enum ({@see AppAction}),
 * refused by {@see AppActionRecorder} unless it is a bounded identifier;
 * `reason` is a closed package enum ({@see AppActionReason}).
 *
 * THE ONE STRING THAT IS NOT AN IDENTIFIER, named rather than left to be
 * found: `on_behalf_of`. D4 requires the agency a delegated operator
 * acts for, and it is issuer-minted display text — bounded to 120
 * characters and rejected for control characters by
 * {@see AssertionVerifier}, and
 * nothing more than that. It is not free text the APP or a REQUEST can
 * write — no app-supplied value reaches this column on any path — but it
 * is not an identifier either, and calling the schema free-text-free
 * without saying so would be the kind of sentence this package has spent
 * rounds deleting. **Escape it at every sink.**
 *
 * **APPEND-ONLY, and the same enforcement shape as the credential
 * stream.** The model throws on any update or delete; the builder throws
 * on truncate on both the static and query paths
 * ({@see AppActionEventBuilder}); and database triggers, where the
 * driver permits, abort raw row-level UPDATE/DELETE so a `DB::table()`
 * write cannot rewrite history either.
 *
 * **THE RESIDUE, stated honestly rather than claimed away.** This model
 * is the package's enforcement point, and it is not an absolute. Raw
 * `TRUNCATE TABLE` SQL is DDL and the row triggers never see it;
 * privileged schema access can DROP the triggers, and direct file access
 * to a sqlite database rewrites anything. TRUNCATE and DROP enforcement,
 * where an operator wants it, is a DATABASE-PRIVILEGE matter — revoke
 * DDL from the app's connection — not something a model guard can give.
 * Append-only here is by construction, not cryptographic: a compromised
 * instance can tamper with its own history.
 *   Pinned by `tests/AppActionAuditTest.php` — "rejects update and
 *   delete at the model layer", "rejects truncate on both the static and
 *   the query-builder paths" and "rejects raw query-builder update and
 *   delete at the database layer on sqlite".
 *
 * **RETENTION IS DECLARED, AND THE DECLARATION IS THAT NOTHING PRUNES
 * IT.** App-action events are attribution history and this package never
 * deletes one — the same decision already taken for the shadow actor
 * row, and for the same reason: an attribution trail that quietly
 * shortens is one an operator cannot rely on. There is no prune command,
 * no scheduled sweep and no retention setting, and the append-only guard
 * above means even a future one could not delete through this model. The
 * residue is the same database-privilege residue named above.
 *   Pinned by `tests/AppActionAuditTest.php` — "ships no pruning path
 *   for the app-action stream anywhere in src" and "names a pruning path
 *   when the walk meets one".
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
