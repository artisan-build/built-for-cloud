<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

/**
 * The relative-path check the structured re-entry 401 puts in front of
 * its `return_to` field.
 *
 * The 401 hands a value back to a browser that will use it to come back
 * here after re-entry, so it is a REDIRECT TARGET in everything but
 * name — and it is the open-redirect boundary for the whole Console
 * until PR4's enter endpoint brings its own allowlist and signed state
 * (D13). An absolute or scheme-bearing candidate is dropped, never
 * echoed, and the payload falls back to a value the SERVER chose.
 *
 * THE CHECK RUNS ON EVERY DECODED FORM, not just the string as it
 * arrived. Percent-encoding is the whole attack here: `/%2f%2fevil.example`
 * is printable ASCII, single-slash-rooted, and becomes `//evil.example` —
 * another origin — the moment anything decodes it, and `/%5cevil.example`
 * becomes `/\evil.example`, which several browsers normalize to `//`.
 * Double encoding (`/%252f%252fevil.example`) hides it one layer deeper.
 * So the candidate is decoded repeatedly to a FIXED POINT and every form
 * along the way — the raw one included — must independently be a safe
 * relative path. A candidate that will not settle within a small number
 * of rounds is refused rather than decoded further.
 *
 * DOT SEGMENTS ARE REFUSED TOO, and that one is about WHO normalizes.
 * `/admin/../billing` is a legitimately relative path, so every rule
 * above lets it through — and the BROWSER resolves it to `/billing`
 * before it ever reaches this app. Any decision made on the string as
 * written (an allowlist of landing paths, above all) is therefore
 * deciding about a different path from the one that gets requested.
 * Rather than normalize — which would mean this class returning a value
 * the caller did not supply, and every caller having to know that — a
 * candidate carrying a `.` or `..` SEGMENT is refused outright, in every
 * decoded form: `/admin/../billing`, `/admin/%2e%2e/billing` and
 * `/admin/%252e%252e/billing` alike. A dot inside a segment is
 * untouched: `/reports..csv` and `/o..ders` are ordinary paths.
 *
 * **THE PATH IS ESTABLISHED ONCE, BEFORE ANY DECODING, AND EVERY CHECK
 * SHARES IT.** That ordering is the whole of the second round of this
 * fix, and the reason is a defect that survived the first: the query
 * and fragment used to be split off from EACH DECODED FORM, so a
 * candidate could invent a delimiter on the way down and hide a
 * traversal behind it. `/admin%3F/%2e%2e/billing` carries no literal
 * `?`, so its raw path is the whole string and looks clean; decoded it
 * becomes `/admin?/../billing`, at which point a per-form split
 * discarded everything after the new `?` and saw only `/admin`. The
 * browser does no such thing — `%3F` is not a delimiter inside a path —
 * so it resolved the `%2e%2e` and landed on `/billing`. `%23` did the
 * same with a fragment.
 *   So the split happens on the RAW candidate, once. Everything before
 *   the first literal `?` or `#` is the path, for good, and every
 *   decoding round and every check runs against that. A `?` that
 *   appears only after decoding is an ordinary path character, which is
 *   exactly what the browser thinks it is.
 *   Pinned by `tests/ConsoleEnterTest.php` — "refuses a return path
 *   carrying a traversal segment in any decoded form, allowlist or no
 *   allowlist" and "matches the allowlist against the fully decoded
 *   path, not the raw one".
 *
 * ACCEPTED: a single-slash-rooted path made only of printable ASCII with
 * no backslash and no dot segment, which stays one after every decoding
 * round.
 * REJECTED, each for its own reason:
 *
 * - anything not rooted at `/` — `https://evil.example/x`,
 *   `javascript:alert(1)`, `data:…`, and every other scheme;
 * - `//evil.example/x` — protocol-relative, a same-origin-looking string
 *   browsers resolve to another host — and anything that DECODES to one;
 * - any backslash, raw or encoded: `/\evil.example`, `%5c`, `%255c`;
 * - any `.` or `..` PATH SEGMENT, raw or encoded, in any decoded form;
 * - any control character or whitespace, raw or encoded, including the
 *   CR/LF pair that would split a header if this value ever reached one;
 * - anything over the length bound.
 *
 * THE COST, stated plainly: a legitimate path carrying a percent-encoded
 * space or slash — `/orders?q=a%20b`, `/search?q=a%2Fb` — is refused, and
 * the caller lands on `/` instead of where they were. That is the safe
 * direction for a value that becomes a redirect, and it is a deliberate
 * false negative rather than an oversight.
 *
 * ONE RESIDUE, and matching the CANONICAL path is what bounds it: an
 * intermediary that normalizes differently from this class. Some
 * proxies decode `%2F` into a path separator before forwarding. That
 * cannot surprise a decision made here, because the decision is made
 * on the decoded form too — `/adm%2fin` is judged as `/adm/in`, which
 * is what such a proxy would produce — but it is the reason the
 * comparison is made on the canonical value rather than on the
 * spelling, and it is why a candidate whose meaning is not settled
 * within {@see MAX_DECODE_ROUNDS} is refused rather than resolved.
 *
 * The check is syntactic and total: no normalization, no "clean it up
 * and use it". A candidate is returned exactly as it arrived or refused.
 * {@see canonicalPath()} is the one exception and it is not an
 * exception to that rule: it answers a different question — what path
 * will actually be requested — for callers that must DECIDE about a
 * path rather than emit one.
 */
final class ConsoleReturnTo
{
    /**
     * Comfortably above any real in-app path and far below anything a
     * caller could use the error body to amplify with.
     */
    public const int MAX_LENGTH = 2048;

    /**
     * How many decoding rounds a candidate gets to reach a fixed point.
     * Real values need zero or one; a candidate still changing after
     * this many is refused rather than decoded indefinitely.
     */
    private const int MAX_DECODE_ROUNDS = 4;

    /**
     * The candidate if it is a safe relative path in every form, else
     * null.
     */
    public static function relative(mixed $candidate): ?string
    {
        return is_string($candidate) && self::settle($candidate) !== null ? $candidate : null;
    }

    /**
     * THE CANONICAL PATH: the fully decoded path portion of a safe
     * candidate — what will actually be requested — or null when
     * {@see relative()} would refuse it.
     *
     * It exists because a decision about a return path must be made
     * about the path that will be requested, not about its spelling.
     * `/%61dmin/users` and `/admin/users` are the same path, and an
     * allowlist that compared the raw strings would answer differently
     * for them.
     *
     * It carries **no query and no fragment**: those are split off the
     * RAW candidate before anything is decoded (see the class docblock
     * for the defect that ordering closes), so a caller matching against
     * this value can never be shown a shorter path than the one the
     * browser will resolve. And it can carry no `.` or `..` segment,
     * because a candidate that has one is refused outright.
     *
     * The REDIRECT still uses {@see relative()}'s verbatim answer — this
     * class never hands a caller a value the caller did not supply.
     * This is for deciding ABOUT a path, not for emitting one.
     */
    public static function canonicalPath(mixed $candidate): ?string
    {
        return is_string($candidate) ? self::settle($candidate) : null;
    }

    /**
     * Split the raw candidate ONCE, decode its path to a fixed point,
     * and require every form along the way — the raw one included — to
     * be safe. Returns the settled PATH, or null.
     *
     * One routine, used by every public entry point, so "what is safe"
     * and "what path this means" can never be answered by two pieces of
     * code that disagree.
     *
     * The suffix (query and fragment) is decoded and checked too, but
     * only for the character rules: a `..` in a query names no
     * directory, and refusing `/orders?sort=..` would cost a caller a
     * legitimate path for nothing.
     */
    private static function settle(string $candidate): ?string
    {
        if ($candidate === '' || strlen($candidate) > self::MAX_LENGTH) {
            return null;
        }

        // The split is on the RAW value and it is final. A delimiter
        // that appears only after decoding is an ordinary path
        // character — which is exactly what a browser treats it as.
        $cut = strcspn($candidate, '?#');
        $path = substr($candidate, 0, $cut);
        $suffix = substr($candidate, $cut);

        $settled = self::fixedPoint($path, requireSafePathSegments: true);

        if ($settled === null) {
            return null;
        }

        return $suffix === '' || self::fixedPoint($suffix, requireSafePathSegments: false) !== null
            ? $settled
            : null;
    }

    /**
     * Decode one piece to a fixed point, checking every form.
     *
     * `$requireSafePathSegments` is what separates the two pieces: the
     * PATH must additionally be rooted at a single `/` and free of dot
     * segments; the query and fragment must only be free of the
     * characters no redirect target may carry.
     */
    private static function fixedPoint(string $piece, bool $requireSafePathSegments): ?string
    {
        $form = $piece;

        for ($round = 0; $round <= self::MAX_DECODE_ROUNDS; $round++) {
            if (! self::isSafeForm($form, $requireSafePathSegments)) {
                return null;
            }

            $decoded = rawurldecode($form);

            if ($decoded === $form) {
                // Fixed point reached and every form so far was safe.
                return $form;
            }

            $form = $decoded;
        }

        // Still changing after the last round: refuse rather than guess
        // what it eventually becomes.
        return null;
    }

    /**
     * The first candidate that survives {@see relative()}, or `/`.
     *
     * The fallback is a server-chosen constant rather than anything
     * derived from the refused input: a caller who supplies a hostile
     * `return_to` gets the app root, never a cleaned-up version of what
     * they sent.
     *
     * @param  list<mixed>  $candidates
     */
    public static function firstRelative(array $candidates): string
    {
        foreach ($candidates as $candidate) {
            $relative = self::relative($candidate);

            if ($relative !== null) {
                return $relative;
            }
        }

        return '/';
    }

    /**
     * One form of one piece, judged on its own.
     *
     * The character class is printable ASCII minus the backslash: a raw
     * byte outside it has no business in a URL, and refusing it costs a
     * caller only the need to percent-encode — which, per the class
     * docblock, this check then refuses too. That is the point: the
     * value is a redirect target, not a payload.
     */
    private static function isSafeForm(string $value, bool $requireSafePathSegments): bool
    {
        if ($value === '' || strlen($value) > self::MAX_LENGTH) {
            return false;
        }

        if ($requireSafePathSegments) {
            if (! str_starts_with($value, '/') || str_starts_with($value, '//')) {
                return false;
            }

            if (self::hasDotSegment($value)) {
                return false;
            }
        }

        return preg_match('/[^\x21-\x7E]|\\\\/', $value) === 0;
    }

    /**
     * Whether this PATH form carries a `.` or `..` segment.
     *
     * It is given a path and nothing else — the query and fragment were
     * split off the raw candidate before any decoding, which is what
     * stops a traversal hiding behind a delimiter that only appears
     * once something is decoded. Whole segments only, so a dot INSIDE a
     * segment — `/reports..csv`, `/o..ders` — is an ordinary path and
     * passes.
     */
    private static function hasDotSegment(string $path): bool
    {
        foreach (explode('/', $path) as $segment) {
            if ($segment === '.' || $segment === '..') {
                return true;
            }
        }

        return false;
    }
}
