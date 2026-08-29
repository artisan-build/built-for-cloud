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
 * ACCEPTED: a single-slash-rooted path made only of printable ASCII with
 * no backslash, which stays one after every decoding round.
 * REJECTED, each for its own reason:
 *
 * - anything not rooted at `/` — `https://evil.example/x`,
 *   `javascript:alert(1)`, `data:…`, and every other scheme;
 * - `//evil.example/x` — protocol-relative, a same-origin-looking string
 *   browsers resolve to another host — and anything that DECODES to one;
 * - any backslash, raw or encoded: `/\evil.example`, `%5c`, `%255c`;
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
        if (! is_string($candidate)) {
            return null;
        }

        $form = $candidate;

        for ($round = 0; $round <= self::MAX_DECODE_ROUNDS; $round++) {
            if (! self::isSafeRelativePath($form)) {
                return null;
            }

            $decoded = rawurldecode($form);

            if ($decoded === $form) {
                // Fixed point reached and every form so far was safe.
                return $candidate;
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

        return preg_match('/[^\x21-\x7E]|\\\\/', $value) === 0;
    }
}
