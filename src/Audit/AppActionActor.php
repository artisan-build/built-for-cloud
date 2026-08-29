<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Audit;

use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\Console\ActingPrincipal;
use ArtisanBuild\BuiltForCloud\Console\AssertionVerifier;
use ArtisanBuild\BuiltForCloud\Console\DelegatedActor;
use ArtisanBuild\BuiltForCloud\Console\DelegatedClaims;
use ArtisanBuild\BuiltForCloud\Credential;
use Illuminate\Contracts\Auth\Authenticatable;
use LogicException;

/**
 * WHO performed an app action: one of the three principals
 * {@see AppActorType} names, their identifier, and — for a delegated
 * actor only — the agency they acted for (D4).
 *
 * **THE CONSTRUCTOR IS PRIVATE, and that is what holds D4's shape.**
 * `on_behalf_of` belongs to a delegated session and to nothing else: a
 * local user acts for the deployment they log in to, and a credential
 * acts for itself. Rather than validating that after the fact, the two
 * non-delegated named constructors do not TAKE an `on_behalf_of` at all,
 * so a local-user or api-token actor cannot be constructed carrying one.
 * {@see delegated()} takes it and passes it through verbatim, `null`
 * included — a session whose handoff carried no agency records none, and
 * the issuer is never substituted for it. Fabricating an agency here
 * would put a customer's name on an action nobody said they authorised.
 *   Pinned by `tests/AppActionAuditTest.php` — "carries the agency a
 *   delegated handoff named", "records a delegated event with no agency
 *   as null rather than inventing one" and "cannot construct a local
 *   user or api token actor that carries an agency at all".
 *
 * **THE DELEGATED REF IS TYPE-QUALIFIED.** It is
 * {@see DelegatedActor::getAuthIdentifier()} — `bfc-console:{id}` —
 * never the bare key. `bfc_delegated_actors` is an ordinary
 * auto-increment table in the SAME id space `users` occupies, so actor 7
 * and user 7 both exist routinely, and an app-action row that said `7`
 * would read as user 7 having done it. The qualifier is applied by
 * going through the model's own accessor rather than by string
 * concatenation here, so there is one place that decides what a
 * delegated identity looks like.
 *   Pinned by `tests/AppActionAuditTest.php` — "names a delegated actor
 *   by its type-qualified identity, where a user with the same numeric
 *   id also exists".
 *
 * **IDS ONLY.** Like {@see AuditActor}, this
 * carries identifiers and never PII the package chose to include. The
 * honest residue, named rather than left to be found: `ref` is the
 * host's OWN primary key for a local user, so a deployment that keys
 * `users` on an email address stores an email here. That is the host's
 * schema decision showing through an id column, not free text this
 * package invites, and it is the same residue the shipped credential
 * stream's `actor_ref` already carries.
 */
final readonly class AppActionActor
{
    private function __construct(
        public AppActorType $type,
        public string $ref,
        /** The agency a delegated operator acts for (D4), or null. Never non-null for any other type. */
        public ?string $onBehalfOf = null,
    ) {}

    /**
     * The host application's own authenticated human.
     *
     * @throws LogicException when the principal has no scalar identifier — an actor
     *                        the package cannot name is not one it will guess at
     */
    public static function localUser(Authenticatable $user): self
    {
        return new self(AppActorType::LocalUser, self::identifierOf($user));
    }

    /**
     * A credential acting on its own behalf, named by its opaque id.
     */
    public static function apiToken(Credential $credential): self
    {
        return new self(AppActorType::ApiToken, self::identifierOf($credential));
    }

    /**
     * A delegated operator, named by the type-qualified identity, acting
     * for the agency THIS session's handoff named — or for none.
     *
     * The agency parameter is typed `?string` and is passed VERBATIM.
     * Both callers take it from {@see DelegatedClaims}, the session's own
     * copy, and never from the actor row's `last_handoff_on_behalf_of`:
     * that column is shared by every live session for the same subject,
     * so a later handoff naming a different agency would retroactively
     * re-attribute this action to it. That is a rule about where the
     * value comes from, which this signature cannot enforce and does not
     * claim to — what it enforces is that only a DELEGATED actor has a
     * parameter to put one in.
     *
     * **Issuer-supplied free text, bounded and control-character-free by
     * {@see AssertionVerifier} and
     * nothing more. Escape at every sink.**
     */
    public static function delegated(DelegatedActor $actor, ?string $onBehalfOf): self
    {
        return new self(AppActorType::DelegatedActor, $actor->getAuthIdentifier(), $onBehalfOf);
    }

    /**
     * The actor for THIS REQUEST, taken from the ONE
     * {@see ActingPrincipal} the resolver already built for it (Console
     * PRD D14).
     *
     * **This is the whole of D14's audit half, and it is why this method
     * takes the resolved principal rather than resolving anything.** The
     * resolver decides which guard the request acts under, once; a
     * recorder that asked `Auth::`, a guard, or `$request->user()` a
     * second time could disagree with the principal the request actually
     * acted as, and an audit line naming the wrong one of two live
     * identities is exactly the failure D14 exists to forbid. On a route
     * guarded by the app's own guard while a delegated session is also
     * live, the acting principal is the LOCAL user, and so is this
     * actor — the delegated actor on the same request is reported by
     * {@see ActingPrincipal::$delegatedActor} and is deliberately not
     * what attributes.
     *   Pinned by `tests/AppActionAuditTest.php` — "attributes to the
     *   acting principal and not to the delegated session co-resident on
     *   the same request".
     *
     * A resolution with no principal — nobody acting, or a delegated
     * session that was REFUSED — throws. An app action is a thing
     * somebody did; recording one with the actor left blank would be a
     * row asserting less than the stream promises, and the fail-closed
     * direction is to refuse the emission.
     *
     * @throws LogicException when nobody is acting on this request
     */
    public static function fromActingPrincipal(ActingPrincipal $principal): self
    {
        // The delegated branch reads `onBehalfOf` off the SAME resolution
        // it reads the principal off: ActingPrincipal builds both from
        // this session's own DelegatedClaims in one step, so the two
        // halves of the attribution cannot have come from different
        // handoffs.
        if ($principal->delegated && $principal->principal instanceof DelegatedActor) {
            return self::delegated($principal->principal, $principal->onBehalfOf);
        }

        return match (true) {
            $principal->delegated => throw self::unattributable(),
            $principal->principal instanceof Credential => self::apiToken($principal->principal),
            $principal->principal instanceof Authenticatable => self::localUser($principal->principal),
            default => throw self::unattributable(),
        };
    }

    /**
     * The principal's identifier as a string, or a refusal.
     *
     * `getAuthIdentifier()`'s contract return type is `mixed`, and
     * anything that is not a scalar id is no id at all here — a row
     * carrying `Array` or an empty string would name nobody while
     * looking like it named someone.
     */
    private static function identifierOf(Authenticatable $principal): string
    {
        $identifier = $principal->getAuthIdentifier();

        if (! is_int($identifier) && ! is_string($identifier)) {
            throw self::unattributable();
        }

        $identifier = (string) $identifier;

        return $identifier === '' ? throw self::unattributable() : $identifier;
    }

    private static function unattributable(): LogicException
    {
        return new LogicException(
            'An app-action event names the principal that performed it; there is no unattributed app action.',
        );
    }
}
