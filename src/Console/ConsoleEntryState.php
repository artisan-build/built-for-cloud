<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

use ArtisanBuild\BuiltForCloud\Exceptions\ConsoleEntryRefused;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ConsoleEnter;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Throwable;

/**
 * D13's SIGNED STATE: the handoff state that travels beside a console
 * assertion, and the return path it carries.
 *
 * WHY IT IS SHAPED LIKE THIS, because the obvious shape is not
 * available here. The classic anti-CSRF state is one the RELYING PARTY
 * planted in the caller's session before the round trip and compares on
 * the way back. This app cannot: the handoff is a cross-site POST from
 * the issuer's page, and a `SameSite=Lax` session cookie — Laravel's
 * default — is NOT sent on a cross-site POST, so at the moment the
 * entry arrives the app has no prior state with that browser at all.
 * Nor can the app verify a MAC the issuer computed: it holds only
 * PUBLIC keys ({@see ConsoleKeyring}), by design, so the one thing it
 * can verify the issuer produced is an Ed25519 signature.
 *
 * So the state is bound to the mint by the mint's own signature: the
 * state travels as an opaque field, its sha256 digest travels INSIDE
 * the assertion as the `state` claim, and this class accepts a state
 * only when the two agree. The digest is checked BEFORE the state is
 * decoded, so no attacker-supplied bytes are ever parsed on the
 * strength of anything but the vendor's signature.
 *
 * WHAT THAT BUYS, exactly:
 *
 *  - **Open redirect is closed.** The return path is not a request
 *    field: it is inside a blob the vendor signed, and it must
 *    additionally be a safe same-origin relative path in every
 *    percent-decoded form ({@see ConsoleReturnTo}) — traversal
 *    segments included — and inside the deployment's own allowlist,
 *    matched against the CANONICAL path, with the configured prefixes
 *    canonicalized the same way. Substituting it invalidates the
 *    digest; supplying an absolute, protocol-relative or traversing one
 *    is refused even when the vendor signed it.
 *      Pinned by `tests/ConsoleEnterTest.php` — "refuses a return path
 *      that is not a safe same-origin relative path, whatever the mint
 *      signed" and "refuses a return path carrying a traversal segment
 *      in any decoded form, allowlist or no allowlist".
 *  - **A state cannot be moved between mints.** The digest is claimed
 *    by one assertion, and that assertion's `jti` burns once, so a
 *    captured state is worth nothing beside a different token and
 *    nothing twice beside its own.
 *
 * WHAT IT DOES NOT BUY, stated rather than implied, because "kills
 * login-CSRF" is more than this design can hold: **an attacker who can
 * obtain a legitimately-minted assertion for their OWN issuer identity
 * can still auto-submit it in a victim's browser**, leaving that
 * browser entered as the attacker — the forced-login shape of CSRF. No
 * state parameter closes that here, because every state the attacker
 * needs is one the issuer minted for them. What bounds it instead is
 * the assertion's own 60-120 second TTL and its single-use burn (D12):
 * the window is short, the token is spent, and the delegated session
 * carries the ATTACKER's audited identity rather than the victim's, so
 * nothing the victim does under it is attributed to the victim. The
 * residue is that a victim may act inside an app under an identity they
 * did not choose. Closing it needs a state the APP planted, which needs
 * a request that carries the app's cookie, which the cross-site POST is
 * not.
 *   Pinned by `tests/ConsoleEnterTest.php` — "refuses an entry whose
 *   state was tampered with after the mint signed it", "refuses an
 *   entry that presents no state at all", "refuses a mint that signed
 *   no state, whatever state is presented" and "refuses a state lifted
 *   from a different mint".
 *
 * The state's own shape is deliberately minimal and OPEN: unpadded
 * base64url of a JSON object carrying `return_to`. Unknown members are
 * ignored rather than refused, so the issuer can grow the payload (D13
 * puts the switcher roster in the mint) without a contract break here.
 * {@see ConsoleEnter} is the only caller.
 */
final readonly class ConsoleEntryState
{
    /** The request field the state arrives in. */
    public const string FIELD = 'state';

    /** The member of the decoded state that names where to land. */
    public const string RETURN_TO = 'return_to';

    /**
     * A whole-state size bound, applied before anything is decoded.
     * Comfortably above a base64url'd object carrying a maximal
     * {@see ConsoleReturnTo::MAX_LENGTH} path, and far below anything
     * an attacker could spend CPU with.
     */
    public const int MAX_LENGTH = 4096;

    /** How deep the state's JSON may nest before it is malformed. */
    private const int MAX_JSON_DEPTH = 8;

    private function __construct(
        /** The validated, same-origin relative path this entry lands on. */
        public string $returnTo,
    ) {}

    /**
     * Bind a presented state to the mint that signed it, and read the
     * return path out of it.
     *
     * The order is the security property: the digest is compared before
     * a single byte is decoded, and the return path is validated after.
     *
     * @throws ConsoleEntryRefused when the state is absent, unsigned, mismatched, malformed, or names a path this deployment will not redirect to
     */
    public static function bind(Assertion $assertion, mixed $state): self
    {
        if ($assertion->stateDigest === null) {
            // A mint that signed no state cannot enter. The return path
            // would otherwise be a request field with nothing behind
            // it, which is the whole of what D13 forbids.
            throw ConsoleEntryRefused::because(ConsoleEntryRefusalReason::StateUnsigned, $assertion->id);
        }

        if (! is_string($state) || $state === '') {
            throw ConsoleEntryRefused::because(ConsoleEntryRefusalReason::StateMissing, $assertion->id);
        }

        if (strlen($state) > self::MAX_LENGTH) {
            throw ConsoleEntryRefused::because(ConsoleEntryRefusalReason::StateMalformed, $assertion->id);
        }

        if (! hash_equals($assertion->stateDigest, hash('sha256', $state))) {
            throw ConsoleEntryRefused::because(ConsoleEntryRefusalReason::StateMismatch, $assertion->id);
        }

        return new self(self::returnPath($assertion, self::decode($assertion, $state)));
    }

    /**
     * The state's members, decoded only after the digest has held.
     *
     * @return array<string, mixed>
     */
    private static function decode(Assertion $assertion, string $state): array
    {
        try {
            $decoded = json_decode(
                Base64UrlSafe::decodeNoPadding($state),
                true,
                self::MAX_JSON_DEPTH,
                JSON_THROW_ON_ERROR,
            );
        } catch (Throwable $failure) {
            throw ConsoleEntryRefused::because(
                ConsoleEntryRefusalReason::StateMalformed,
                $assertion->id,
                $failure,
            );
        }

        if (! is_array($decoded)) {
            throw ConsoleEntryRefused::because(ConsoleEntryRefusalReason::StateMalformed, $assertion->id);
        }

        /** @var array<string, mixed> */
        return $decoded;
    }

    /**
     * The return path: relative in every decoded form, and inside the
     * deployment's allowlist.
     *
     * There is no fallback. {@see ConsoleReturnTo::firstRelative()}
     * lands a refused candidate on `/`, which is right for the re-entry
     * 401 — it is telling an ALREADY-AUTHENTICATED operator's browser
     * where to go — and wrong here: a return path the vendor signed and
     * this deployment will not honour is a disagreement about where an
     * entry may land, and silently landing somewhere else would hide
     * it.
     *
     * @param  array<string, mixed>  $state
     */
    private static function returnPath(Assertion $assertion, array $state): string
    {
        $raw = $state[self::RETURN_TO] ?? null;

        $candidate = ConsoleReturnTo::relative($raw);
        // The allowlist decides about the path that will be REQUESTED —
        // the canonical one, query and fragment already split off the
        // RAW value and gone. The redirect emits what the issuer signed.
        $canonical = ConsoleReturnTo::canonicalPath($raw);

        if ($candidate === null || $canonical === null || ! self::allowed($canonical)) {
            throw ConsoleEntryRefused::because(ConsoleEntryRefusalReason::ReturnPathRefused, $assertion->id);
        }

        return $candidate;
    }

    /**
     * Whether the deployment's own allowlist covers this path (D13).
     *
     * AN EMPTY ALLOWLIST IS THE DEFAULT AND MEANS "any path in this
     * app", which is said plainly rather than dressed up: with none
     * configured, the bound on a return path is
     * {@see ConsoleReturnTo}'s same-origin-relative check, and that is
     * the check which actually closes open redirect. The allowlist is
     * opt-in NARROWING for a deployment that wants entry confined to
     * the few paths its console links to.
     *
     * **IT IS GIVEN THE CANONICAL PATH, AND SO IS EVERY PREFIX IT
     * COMPARES.** That is the whole of the rule, and it took two rounds
     * to get right. An early revision prefix-matched the raw string,
     * which a signed `/admin/../billing` walked straight through: every
     * syntactic check passed, it matched `/admin`, and the BROWSER
     * resolved it to `/billing`. The next revision matched the decoded
     * string but split query and fragment off EACH DECODED FORM — so
     * `/admin%3F/%2e%2e/billing`, which carries no literal `?`, decoded
     * to `/admin?/../billing`, the split threw away everything after the
     * invented `?`, and the comparison saw `/admin` while the browser
     * saw a traversal. `%23` did the same with a fragment.
     *
     * {@see ConsoleReturnTo::canonicalPath()} now establishes the path
     * ONCE — split off the raw value, decoded to a fixed point, and
     * refused outright if any form carries a dot segment — so the
     * string being matched IS the path that will be requested. This
     * method does no splitting, no decoding and no normalizing of its
     * own; there is one canonical value and every check shares it.
     *
     * THE CONFIGURED PREFIXES GO THROUGH THE SAME DOOR. A prefix is
     * canonicalized before it is compared, so `/adm%69n` and `/admin/`
     * mean what they look like — and a prefix that is not a safe in-app
     * path matches NOTHING rather than being trimmed into something. An
     * earlier revision reached the wildcard branch by `rtrim`-ing to the
     * empty string, which `//` and `///` also do: a configured `//`
     * silently allowed every path. Only a literal `/` is the wildcard
     * now, and it is the one prefix that survives canonicalization to
     * the root.
     *   Pinned by `tests/ConsoleEnterTest.php` — "refuses a return path
     *   carrying a traversal segment in any decoded form, allowlist or
     *   no allowlist", "matches the allowlist against the fully decoded
     *   path, not the raw one" and "refuses an allowlist prefix that is
     *   not itself a safe in-app path, rather than widening on it".
     *
     * AN EMPTY ALLOWLIST IS THE DEFAULT AND MEANS "any path in this
     * app". Matching is at a SEGMENT BOUNDARY, so `/admin` covers
     * `/admin` and `/admin/users` and never `/admin-secrets`.
     */
    private static function allowed(string $canonicalPath): bool
    {
        $configured = config('built-for-cloud.console.return_path_allowlist', []);

        if (! is_array($configured) || $configured === []) {
            return true;
        }

        foreach ($configured as $prefix) {
            // A prefix that is not itself a safe in-app path matches
            // nothing. It is skipped rather than trimmed or guessed at:
            // a typo in an allowlist must never widen it.
            $canonicalPrefix = ConsoleReturnTo::canonicalPath($prefix);

            if ($canonicalPrefix === null) {
                continue;
            }

            $normalized = rtrim($canonicalPrefix, '/');

            // Only the root survives canonicalization to the empty
            // string, and the root is the deliberate wildcard.
            if ($normalized === '' || $canonicalPath === $normalized || str_starts_with($canonicalPath, $normalized.'/')) {
                return true;
            }
        }

        return false;
    }
}
