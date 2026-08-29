<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use SensitiveParameter;

/**
 * The user provider behind the `bfc-console` guard: the ONLY way a
 * delegated session turns back into a principal.
 *
 * Four of the six {@see UserProvider} methods exist to authenticate a
 * SECRET, and this provider answers none of them. `retrieveByCredentials`
 * and `validateCredentials` return null/false unconditionally — not
 * "when the credentials do not match", but ALWAYS, for every input,
 * including a correct one, because there is nothing here to match
 * against: the table has no password column and
 * {@see DelegatedActor::getAuthPassword()} is the empty string every
 * hasher already refuses. `retrieveByToken` is null for the same reason
 * (no remember-token column, no "remember me" for a delegated session),
 * and `updateRememberToken` has nothing to write.
 *
 * THIS IS WHERE §4.3's "no login path" IS ACTUALLY HELD, together with
 * {@see ConsoleGuard} having no `attempt()`, no `loginUsingId()` and no
 * remember-me path at all. The two together mean the question is never
 * asked and could not be answered yes if it were — a structural
 * property, not a convention, and not something the model's own methods
 * are doing.
 *
 * `retrieveById` is the identifier boundary, and it is strict in three
 * separate ways:
 *
 *  1. **The type qualifier is mandatory.** The identifier must be a
 *     string carrying the `bfc-console:` prefix; a bare key — integer 7
 *     or the string "7", exactly what a `users` id looks like — resolves
 *     to NOTHING. Combined with
 *     {@see DelegatedActor::getAuthIdentifier()}, which only ever emits
 *     the qualified form, the two id spaces cannot cross in either
 *     direction.
 *  2. **The suffix must be a CANONICAL positive decimal**, matched
 *     before any query runs. `1junk`, `01`, ` 1`, `+1`, `1.0`, `-1`, `0`
 *     and a 30-digit number are all refused without touching the
 *     database. Canonical rather than merely numeric because a
 *     non-canonical suffix means two different strings would name one
 *     row — and an identity with two spellings is an identity that can
 *     be smuggled past a comparison somewhere else. The range bound
 *     keeps an oversized value away from a driver that would silently
 *     saturate or wrap it.
 *  3. **The retrieved row must emit exactly the identifier that was
 *     asked for.** Belt to the braces above: if any future key type,
 *     driver coercion or model override made the round trip lossy, the
 *     lookup fails rather than returning "close enough".
 *
 * A DEACTIVATED actor does not resolve. That is where offboarding takes
 * effect: the row survives (it is the referent of past audit
 * attribution) and simply stops being a principal, so a session that
 * outlived the deactivation stops authenticating on its very next
 * request rather than at the end of its clocks.
 *
 * D7's CLOCKS ARE NOT CHECKED HERE. This provider answers identity and
 * containment only; the absolute assertion-age cap belongs to
 * {@see ConsoleGuard}, which evaluates it BEFORE asking this provider
 * anything and destroys the session on refusal. That is the whole of the
 * cap, and it is unavoidable rather than defended in two places: this
 * provider is only ever reached through that guard, because the guard is
 * what the `bfc-console` entry in `auth.guards` resolves to.
 */
final class DelegatedActorProvider implements UserProvider
{
    /**
     * A canonical positive decimal with no leading zero, bounded to 18
     * digits so the value is always inside PHP's and every supported
     * driver's signed 64-bit range.
     */
    private const string CANONICAL_KEY = '/^[1-9][0-9]{0,17}\z/';

    /**
     * @param  mixed  $identifier
     */
    public function retrieveById($identifier): ?Authenticatable
    {
        $key = self::keyFrom($identifier);

        if ($key === null) {
            return null;
        }

        /** @var DelegatedActor|null $actor */
        $actor = DelegatedActor::query()
            ->whereKey($key)
            ->whereNull('deactivated_at')
            ->first();

        if ($actor === null) {
            return null;
        }

        // The round trip must be exact: the row we found has to answer
        // with the identifier we were handed, character for character.
        return hash_equals($actor->getAuthIdentifier(), (string) $identifier) ? $actor : null;
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
        if (! is_string($identifier) || ! str_starts_with($identifier, DelegatedActor::IDENTIFIER_PREFIX)) {
            return null;
        }

        $key = substr($identifier, strlen(DelegatedActor::IDENTIFIER_PREFIX));

        return preg_match(self::CANONICAL_KEY, $key) === 1 ? $key : null;
    }

    /**
     * Whether a stored `user_id` sits inside the RESERVED delegated
     * namespace, canonical or not. Deliberately broader than
     * {@see keyFrom()}: `bfc-console:1junk` names no actor, but it is
     * still a value that must never reach a host-app user provider,
     * where a driver's own coercion decides what it means.
     */
    public static function isReservedIdentifier(mixed $identifier): bool
    {
        return is_string($identifier) && str_starts_with($identifier, DelegatedActor::IDENTIFIER_PREFIX);
    }

    /**
     * Always null: there is no remember-token column and no cookie a
     * delegated session could be recalled from.
     *
     * @param  mixed  $identifier
     */
    public function retrieveByToken($identifier, #[SensitiveParameter] $token): ?Authenticatable
    {
        return null;
    }

    /**
     * A no-op: there is no remember-token column to write. Unreachable
     * in practice — {@see ConsoleGuard} never remembers a login, so
     * nothing generates a token to store.
     */
    public function updateRememberToken(Authenticatable $user, #[SensitiveParameter] $token): void
    {
        // No remember-token column exists on bfc_delegated_actors.
    }

    /**
     * Always null, for EVERY input including a well-formed one: there is
     * no credential of any kind that names a delegated actor.
     *
     * @param  array<string, mixed>  $credentials
     */
    public function retrieveByCredentials(#[SensitiveParameter] array $credentials): ?Authenticatable
    {
        return null;
    }

    /**
     * Always false, for EVERY input — including the actual principal and
     * a correct-looking secret. This is not "these credentials did not
     * match"; there is nothing to match against, and nothing built on
     * this provider can ever say yes.
     *
     * @param  array<string, mixed>  $credentials
     */
    public function validateCredentials(Authenticatable $user, #[SensitiveParameter] array $credentials): bool
    {
        return false;
    }

    /**
     * @param  array<string, mixed>  $credentials
     */
    public function rehashPasswordIfRequired(Authenticatable $user, #[SensitiveParameter] array $credentials, bool $force = false): void
    {
        // Nothing to rehash: there is no password anywhere in this
        // principal type.
    }
}
