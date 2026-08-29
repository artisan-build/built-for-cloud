<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Session\Session;

/**
 * D7's ABSOLUTE assertion-age cap, and the one place it is decided.
 *
 * Two clocks bound a delegated session and they are not the same thing:
 *
 *  - the SLIDING idle window is Laravel's own (`session.lifetime`,
 *    120 minutes by default), and this package does not touch it. It
 *    slides on every request, and it is the reason an operator who walks
 *    away is logged out;
 *  - the ABSOLUTE cap below does NOT slide. It is measured from the
 *    assertion's `iat` — the vendor's mint, not this app's session start
 *    — and no amount of activity moves it. It is the reason a delegated
 *    operator removed at the vendor loses this app within a bounded
 *    time whether or not this app can reach the vendor.
 *
 * The cap is a CONSTANT, not a config key, on purpose. It is the
 * worst-case revocation window the fleet promises for a delegated
 * operator (Console PRD D7: two hours), and a per-app knob would let one
 * deployment quietly widen a guarantee the vendor makes on behalf of all
 * of them. An app that wants a tighter delegated session already has
 * one: shorten `session.lifetime`.
 *
 * FAIL CLOSED. {@see evaluate()} answers null only when it has READ a
 * marker and MEASURED an age inside the cap. Every other outcome —
 * missing, non-integer, or dated further ahead than the configured clock
 * skew — is a refusal. There is deliberately no "assume it just started"
 * branch: an unreadable marker is the exact state an attacker who could
 * influence session contents would aim for, and it is also the state a
 * botched deploy leaves behind.
 *
 * The clock is PURE: it reads the session and the clock and writes
 * nothing. Invalidating the session is {@see ConsoleGuard}'s, and
 * answering the request is {@see EnsureConsoleSession}'s.
 */
final class ConsoleSessionClock
{
    /**
     * The absolute cap, in minutes, measured from the assertion's `iat`
     * (Console PRD D7). Two hours: the stated worst-case revocation
     * window for an ACTIVE delegated operator.
     */
    public const int ASSERTION_AGE_CAP_MINUTES = 120;

    /**
     * Whether this delegated session may continue, and if not, why.
     * Null means fresh.
     */
    public static function evaluate(Session $session, CarbonImmutable $now): ?ConsoleReentryReason
    {
        $issuedAt = self::issuedAtTimestamp($session);

        if ($issuedAt === null) {
            // Missing or unparseable: the age cannot be established, so
            // the session is treated exactly as expired.
            return ConsoleReentryReason::SessionInvalidated;
        }

        // A marker dated into the future is a clock disagreement, and
        // the SAME one-sided skew the assertion verifier already spends
        // applies here for the same reason: the value written at enter
        // is the ISSUER's `iat`, which may legitimately sit a few
        // seconds ahead of this server without anything being wrong.
        // Beyond that tolerance it is not a disagreement any more — an
        // `iat` far ahead would postpone the cap by exactly that
        // distance — so it fails closed rather than buying time.
        if ($issuedAt > $now->getTimestamp() + self::clockSkewSeconds()) {
            return ConsoleReentryReason::SessionInvalidated;
        }

        return $now->getTimestamp() - $issuedAt >= self::ASSERTION_AGE_CAP_MINUTES * 60
            ? ConsoleReentryReason::AssertionAgeCap
            : null;
    }

    /**
     * The marker as a Unix timestamp, or null when the session does not
     * carry an integer-shaped one. Integer-shaped strings are accepted
     * because a session driver may round-trip an int through text;
     * nothing else is, and no value is coerced.
     */
    private static function issuedAtTimestamp(Session $session): ?int
    {
        $value = $session->get(ConsoleSession::ASSERTION_ISSUED_AT);

        if (is_int($value)) {
            return $value;
        }

        return is_string($value) && preg_match('/^-?\d{1,19}\z/', $value) === 1
            ? (int) $value
            : null;
    }

    /**
     * The same knob {@see AssertionVerifier} spends on the not-yet-valid
     * rule, read here for the same reason and with the same meaning:
     * how far the issuer's clock may run AHEAD of this one. Read
     * defensively — a garbage value falls back to the documented
     * default rather than widening the tolerance.
     */
    private static function clockSkewSeconds(): int
    {
        $seconds = config('built-for-cloud.console.clock_skew_seconds', 5);

        return is_numeric($seconds) && (int) $seconds >= 0 ? (int) $seconds : 5;
    }
}
