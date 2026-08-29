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
 * The check is syntactic and total: no normalization, no "clean it up
 * and use it". A candidate is returned exactly as it arrived or refused.
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
        return is_string($candidate) && self::fixedPoint($candidate) !== null ? $candidate : null;
    }

    /**
     * The FULLY DECODED form of a safe candidate — what the string
     * actually means — or null when {@see relative()} would refuse it.
     *
     * It exists because a decision made about a return path must be made
     * about the path that will be requested, not about its spelling.
     * `/%61dmin/users` and `/admin/users` are the same path, and an
     * allowlist that compared the raw strings would answer differently
     * for them. Traversal is the sharp edge of the same problem and is
     * refused rather than decoded (see the class docblock), so the value
     * returned here is already normalized: it can carry no `.` or `..`
     * segment.
     *
     * The REDIRECT still uses {@see relative()}'s verbatim answer — this
     * class never hands a caller a value the caller did not supply.
     * This is for deciding ABOUT a path, not for emitting one.
     */
    public static function decoded(mixed $candidate): ?string
    {
        return is_string($candidate) ? self::fixedPoint($candidate) : null;
    }

    /**
     * Decode to a fixed point, requiring EVERY form along the way — the
     * raw one included — to be a safe relative path. Returns the settled
     * form, or null.
     *
     * One loop, used by both public entry points, so "what is safe" and
     * "what it decodes to" can never be answered by two pieces of code
     * that disagree.
     */
    private static function fixedPoint(string $candidate): ?string
    {
        $form = $candidate;

        for ($round = 0; $round <= self::MAX_DECODE_ROUNDS; $round++) {
            if (! self::isSafeRelativePath($form)) {
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
     * One form of the candidate, judged on its own.
     *
     * The character class is printable ASCII minus the backslash: a raw
     * byte outside it has no business in a URL path, and refusing it
     * costs a caller only the need to percent-encode — which, per the
     * class docblock, this check then refuses too. That is the point:
     * the value is a redirect target, not a payload.
     */
    private static function isSafeRelativePath(string $value): bool
    {
        if ($value === '' || strlen($value) > self::MAX_LENGTH) {
            return false;
        }

        if (! str_starts_with($value, '/') || str_starts_with($value, '//')) {
            return false;
        }

        if (self::hasDotSegment($value)) {
            return false;
        }

        return preg_match('/[^\x21-\x7E]|\\\\/', $value) === 0;
    }

    /**
     * Whether this form carries a `.` or `..` PATH segment.
     *
     * Query and fragment are cut off first: `/orders?sort=..` and
     * `/docs#..` name no directory, and refusing them would cost a
     * caller a legitimate path for nothing. Whole segments only, so a
     * dot INSIDE a segment — `/reports..csv`, `/o..ders` — is an
     * ordinary path and passes.
     */
    private static function hasDotSegment(string $value): bool
    {
        $path = explode('#', explode('?', $value, 2)[0], 2)[0];

        foreach (explode('/', $path) as $segment) {
            if ($segment === '.' || $segment === '..') {
                return true;
            }
        }

        return false;
    }
}
