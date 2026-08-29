<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

/**
 * The CLOSED enum the structured re-entry 401 carries in its `reason`
 * field (Console PRD D7, as amended). Three values, and a fourth is a
 * contract change: the chrome's interceptor (PR5) and every consuming
 * app's own handler branch on this vocabulary, so it is bounded for the
 * same reason {@see AssertionRefusalReason} is — an enum can never carry
 * attacker-influenced free text into a log line or a rendered page.
 *
 * Unlike {@see AssertionRefusalReason}, this vocabulary IS for the
 * caller: it is telling an already-authenticated operator's browser what
 * to do next, not telling an unauthenticated party why their token
 * failed, so it leaks nothing an oracle could spend.
 */
enum ConsoleReentryReason: string
{
    /**
     * The delegated session's assertion is older than the absolute cap.
     * This is D7's revocation boundary arriving: the session has been
     * invalidated server-side and a fresh mint is required.
     */
    case AssertionAgeCap = 'assertion_age_cap';

    /**
     * A delegated session was present but could not be honoured — the
     * issued-at marker was missing, unparseable, or dated further into
     * the future than the configured clock skew; the session's claims
     * could not be read; or the principal behind it no longer resolves.
     * It is treated EXACTLY as expiry (the session is invalidated
     * server-side and re-entry is required); it reports its own reason
     * because the server did not observe an age past the cap and will
     * not claim it did.
     */
    case SessionInvalidated = 'session_invalidated';

    /** No delegated session on the request at all. */
    case NotAuthenticated = 'not_authenticated';

    /**
     * @return list<string>
     */
    public static function values(): array
    {
        return array_map(
            static fn (self $reason): string => $reason->value,
            self::cases(),
        );
    }
}
