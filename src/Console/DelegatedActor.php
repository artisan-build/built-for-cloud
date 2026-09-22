<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;

/**
 * The SHADOW ACTOR: the stable identity of a delegated human this
 * deployment has admitted through a verified MCP assertion, identified
 * by issuer + subject.
 *
 * WHAT THIS IS NOT — TWICE OVER.
 *
 * It is not a `users` row, and "no password, no login path" holds
 * STRUCTURALLY rather than by anything this class does: nothing in this
 * package resolves this type from a credential, on any driver — the
 * reserved `bfc-console:` identifier namespace is refused by
 * {@see isReservedIdentifier()} before any user provider is asked, and
 * the one principal path that exists ({@see RequestAssertion::publish()})
 * takes a VERIFIED assertion, never a secret. There is therefore no
 * caller anywhere that asks this object for a password, and the
 * password-shaped methods the {@see Authenticatable} contract demands
 * are inert — see {@see getAuthPassword()} for exactly why they return
 * what they do and why they are not the enforcement.
 *   Pinned by `tests/ConsoleDelegatedActorTest.php` — "has no password
 *   or remember-token column" and "type-qualifies the delegated identity
 *   so it can never equal a users id"; and by
 *   `tests/ConsoleCredentialNamespaceTest.php` for the credential half —
 *   no credential resolves one, on any driver.
 *
 * It is also not the live claim store. `last_handoff_display_name`,
 * `last_handoff_role` and `last_handoff_on_behalf_of` are what their
 * names say — the MOST RECENT handoff's claims, kept for operator
 * listings and audit context. The claims a request actually acts under
 * are copied into {@see RequestAssertion} on the current request, and
 * {@see DelegatedClaims} carries them to the acting-principal consumers.
 *   Pinned by `tests/AuthenticateMcpTest.php` — "publishes the assertion
 *   actor and this handoff claims on the request" and "authenticates a
 *   unified bearer, records its use and does not leak the prior request
 *   assertion memo".
 *
 * RESIDUE — NOT ESTABLISHED HERE: these tests do not constrain claim
 * storage or principal resolution implemented by a consuming application
 * outside {@see RequestAssertion}.
 *
 * IDENTITY IS A DIGEST. {@see identityHash()} is the unique key: sha256
 * over a length-delimited encoding of issuer and subject, computed in PHP
 * from the raw bytes. A composite unique index over the two text columns
 * would be exactly as case-sensitive as the database's collation happens
 * to be, and MySQL's common default is not — two humans whose subjects
 * differ only in case would share one row, one role and one audit
 * history. The migration's docblock carries the full reasoning.
 *
 * THE TYPE QUALIFIER. {@see getAuthIdentifier()} returns
 * `bfc-console:{id}` — never the bare integer. The table's key is an
 * ordinary auto-increment in the SAME id space `users` occupies, so
 * actor 7 and user 7 both exist routinely; the qualifier is the only
 * thing that keeps them apart, and it is applied at the one place every
 * caller goes through. That matters because application code that keys
 * caches, policies and ownership checks on `auth()->id()` must never
 * silently read a bare `7` from a delegated principal as user 7's data.
 *
 * @property int $id
 * @property string $identity_hash
 * @property string $issuer
 * @property string $subject
 * @property string $last_handoff_display_name
 * @property string|null $last_handoff_on_behalf_of
 * @property ConsoleRole $last_handoff_role
 * @property CarbonInterface|null $deactivated_at
 * @property CarbonInterface|null $created_at
 * @property CarbonInterface|null $updated_at
 */
final class DelegatedActor extends Model implements Authenticatable
{
    /**
     * The qualifier every delegated identifier carries. It is a RESERVED
     * namespace fleet-wide: {@see isReservedIdentifier()} is what a
     * credential guard consults to refuse any `user_id` starting with it
     * before a user provider is asked.
     * Changing it changes the identity of every delegated actor — an
     * identifier holding the old form simply stops resolving, which is the
     * safe direction.
     */
    public const string IDENTIFIER_PREFIX = 'bfc-console:';

    /**
     * A canonical positive decimal with no leading zero, bounded to 18
     * digits so the value is always inside PHP's and every supported
     * driver's signed 64-bit range.
     */
    private const string CANONICAL_KEY = '/^[1-9][0-9]{0,17}\z/';

    protected $table = 'bfc_delegated_actors';

    /**
     * @var list<string>
     */
    protected $fillable = [
        'identity_hash',
        'issuer',
        'subject',
        'last_handoff_display_name',
        'last_handoff_on_behalf_of',
        'last_handoff_role',
        'deactivated_at',
    ];

    /**
     * The byte-exact identity of an issuer + subject pair.
     *
     * LENGTH-DELIMITED before hashing so that `('ab', 'c')` and
     * `('a', 'bc')` cannot collide: without the lengths, concatenation
     * would let one issuer's suffix and another's subject prefix hash
     * alike, and an issuer boundary that can be shifted is not a
     * boundary. sha256 because the input is attacker-adjacent (the
     * subject is whatever the issuer minted) and a collision here merges
     * two humans into one principal.
     */
    public static function identityHash(string $issuer, string $subject): string
    {
        return hash('sha256', strlen($issuer).':'.$issuer.':'.strlen($subject).':'.$subject);
    }

    /**
     * The primary key a qualified identifier names, or null when the
     * identifier is not one. PUBLIC because the credential guard uses the
     * same rule to recognise — and refuse — the reserved namespace before
     * it hands anything to a user provider; one definition of "this is a
     * delegated identifier", not two that can drift.
     */
    public static function keyFrom(mixed $identifier): ?string
    {
        if (! is_string($identifier) || ! str_starts_with($identifier, self::IDENTIFIER_PREFIX)) {
            return null;
        }

        $key = substr($identifier, strlen(self::IDENTIFIER_PREFIX));

        return preg_match(self::CANONICAL_KEY, $key) === 1 ? $key : null;
    }

    /**
     * Whether a stored `user_id` sits inside the RESERVED delegated
     * namespace, canonical or not. Deliberately broader than
     * {@see keyFrom()}: `bfc-console:1junk` names no actor, but it is
     * still a value that must never reach a user provider, where a
     * driver's own coercion decides what it means.
     */
    public static function isReservedIdentifier(mixed $identifier): bool
    {
        return is_string($identifier) && str_starts_with($identifier, self::IDENTIFIER_PREFIX);
    }

    /**
     * Record a handoff: create the actor for this issuer + subject, or
     * refresh the `last_handoff_*` copy of the one already on file. Keyed
     * on the identity digest, so a SECOND handoff for the same pair
     * updates and never inserts, and a subject differing by one byte —
     * case included — is a different actor.
     *
     * INTERNAL. This is the storage half and it does NOT decide whether
     * the actor may act: it returns deactivated rows too, and it verifies
     * nothing — writing a row here grants nothing, because no principal
     * can be created from it. The one operation that turns an actor into
     * a principal fails closed on a deactivated one under a row lock
     * BEFORE anything is published:
     * {@see RequestAssertion::publish()} for a stateless MCP call (a
     * principal scoped to the one request object, via
     * `AuthenticateMcp`).
     *
     * `deactivated_at` is deliberately never cleared. A fresh, valid
     * assertion means the ISSUER still vouches for the human; it says
     * nothing about the local containment decision that deactivated the
     * row, and letting a handoff undo that would make offboarding survive
     * exactly until the operator clicked again. Nothing in this release
     * reactivates an actor.
     *
     * The race — two handoffs for one new pair arriving together — ends
     * at the unique index rather than in a second row: the loser of the
     * insert re-reads and updates the winner's row.
     */
    public static function recordHandoff(Assertion $assertion): self
    {
        $key = ['identity_hash' => self::identityHash($assertion->issuer, $assertion->subject)];

        $attributes = [
            'issuer' => $assertion->issuer,
            'subject' => $assertion->subject,
            'last_handoff_display_name' => $assertion->displayName,
            'last_handoff_on_behalf_of' => $assertion->onBehalfOf,
            'last_handoff_role' => $assertion->role->value,
        ];

        try {
            /** @var self */
            return self::query()->updateOrCreate($key, $attributes);
        } catch (UniqueConstraintViolationException) {
            /** @var self */
            return self::query()->updateOrCreate($key, $attributes);
        }
    }

    /**
     * Re-read this actor UNDER A ROW LOCK, inside the caller's
     * transaction. Returns null if the row has vanished.
     *
     * This is the read/write boundary redemption and deactivation share.
     * Without it the two interleave: redemption records the handoff,
     * reads `deactivated_at` as null, and is then suspended while a
     * concurrent offboard commits the deactivation — after which the
     * redemption logs in an actor this deployment has just contained.
     * Both sides take the same lock, so one strictly precedes the other
     * and the loser sees the winner's decision.
     *
     * KNOWN LIMIT, stated because the test suite cannot prove otherwise:
     * `lockForUpdate()` compiles to nothing on SQLite, which is what this
     * package's suite runs. The ORDERING is therefore verified only on a
     * driver that implements row locks; what the suite CAN and does
     * verify is that redemption re-reads the row inside the transaction
     * rather than trusting the model it wrote a moment earlier.
     */
    public static function lockedById(int|string $id): ?self
    {
        /** @var self|null */
        return self::query()->whereKey($id)->lockForUpdate()->first();
    }

    /**
     * Contain this actor: it keeps answering for audit attribution and
     * stops resolving as a principal, from its very next request.
     *
     * Takes the SAME row lock redemption takes, in its own transaction,
     * so a deactivation racing a handoff cannot land between that
     * handoff's check and its login. Idempotent: a second deactivation
     * is a no-op and does not move the timestamp, because one
     * containment is one event.
     */
    public function deactivate(): bool
    {
        return (bool) DB::transaction(function (): bool {
            $locked = self::lockedById($this->getKey());

            if ($locked === null || ! $locked->isActive()) {
                return false;
            }

            $locked->forceFill(['deactivated_at' => CarbonImmutable::now()])->save();

            $this->setRawAttributes($locked->getAttributes(), true);

            return true;
        });
    }

    /**
     * Whether this actor still resolves as a principal. Offboarding flips
     * it; nothing else does.
     */
    public function isActive(): bool
    {
        return $this->deactivated_at === null;
    }

    public function getAuthIdentifierName(): string
    {
        return 'id';
    }

    /**
     * The TYPE-QUALIFIED identity — `bfc-console:{id}`, always a string,
     * never the bare key. See the class docblock: this is the one thing
     * standing between a delegated principal and `auth()->id()`-keyed
     * code that has never heard of the Console.
     */
    public function getAuthIdentifier(): string
    {
        return self::IDENTIFIER_PREFIX.$this->getKey();
    }

    /**
     * The empty string, which is what "there is no password column on
     * this table" honestly reduces to.
     *
     * IT IS NOT THE ENFORCEMENT, and it is important not to read it as
     * such. "No login path" is held by there being no code that would
     * accept credentials for this type: no credential resolves one (the
     * reserved-namespace refusal in the credential guard), and the only
     * principal path takes a VERIFIED assertion. Nothing therefore calls
     * this method at all — the callers in Laravel are password-validating
     * providers and `SessionGuard`'s remember-me path, and this type
     * meets neither.
     *
     * An earlier revision threw here to make the claim testable. That was
     * the wrong shape: it made a method nobody calls the load-bearing
     * statement of a property held somewhere else entirely, which is
     * exactly the docblock-stronger-than-the-code failure this codebase
     * has spent rounds on. The empty string is chosen over null because
     * it is what every hasher already treats as "never matches", so even
     * a caller that appeared in some future refactor could not turn it
     * into a match.
     */
    public function getAuthPassword(): string
    {
        return '';
    }

    /**
     * The empty string: there is no password column to name. See
     * {@see getAuthPassword()}.
     */
    public function getAuthPasswordName(): string
    {
        return '';
    }

    /**
     * Always null. Nothing this package writes could ever produce a
     * token to return — a delegated principal's life is bounded by the
     * assertion that published it and by nothing else, and a cookie that
     * outlived that would be the one way the browser got a say in
     * revocation.
     *
     * Null is LOAD-BEARING, not incidental:
     * `EloquentUserProvider::retrieveByToken()` refuses outright on a
     * falsy one, so even a stock provider pointed at this model cannot
     * recall a session from a cookie.
     */
    public function getRememberToken(): ?string
    {
        return null;
    }

    /**
     * A no-op: there is no `remember_token` column to write to.
     *
     * Nothing in this package calls it, so this is not "unreachable" so
     * much as "not on any path taken here". What matters is the
     * observable effect: calling this and saving the model stores
     * nothing and creates no attribute.
     *
     * @param  string  $value
     */
    public function setRememberToken($value): void
    {
        // No remember-token column exists on bfc_delegated_actors.
    }

    /**
     * The empty string: there is no remember-token column, so there is
     * no name to give, and naming one that does not exist would let a
     * provider try to write it.
     *
     * Its caller inside Laravel is
     * `EloquentUserProvider::updateRememberToken()`. A stock provider
     * that reached it could still not recall a session, because
     * `retrieveByToken()` refuses on a falsy {@see getRememberToken()}.
     */
    public function getRememberTokenName(): string
    {
        return '';
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'last_handoff_role' => ConsoleRole::class,
            'deactivated_at' => 'immutable_datetime',
        ];
    }
}
