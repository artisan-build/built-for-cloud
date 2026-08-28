<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

/**
 * The Console's two-value role contract (Console PRD D8). A delegated
 * operator arrives as EXACTLY ONE of these and nothing else is a role,
 * ever: the vendor's own role model (owner, billing admin, support, …)
 * collapses to `admin` or `member` at mint time, and the consuming app
 * maps these two onto its own policies.
 *
 * The vocabulary is deliberately tiny because it is a CONTRACT across
 * every app in the fleet: a third value would have to mean something
 * defensible in an app that has never heard of it, and the honest answer
 * is that it cannot. Apps that need finer grain express it in their own
 * policies keyed off `admin`/`member`, never by inventing a role name
 * the issuer would then have to learn.
 *
 * Roles are per-mint and never cached beyond the session (D8): the role
 * that arrives in an assertion is the role the operator holds right now,
 * and the single-use burn at the enter endpoint (D12, PR4) is what makes
 * a stale claim unreplayable by construction.
 */
enum ConsoleRole: string
{
    /** Full administrative standing inside the app's own policies. */
    case Admin = 'admin';

    /** Ordinary member standing — the least-privilege default. */
    case Member = 'member';

    /**
     * @return list<string>
     */
    public static function values(): array
    {
        return array_map(
            static fn (self $role): string => $role->value,
            self::cases(),
        );
    }
}
