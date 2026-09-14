<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ConsoleVitals;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAbility;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureDashboardCredential;

/**
 * The per-verb-family operator ability vocabulary (PRD 1.10 + GATE-3.7,
 * SEC-8, SEC-V3-06). A credential's `abilities` list names EXACTLY what it
 * may do; a null or empty list grants nothing (fails closed, {@see
 * Credential::hasAbility}), and there is NO wildcard value — `*` is not an
 * ability and matches nothing anywhere in the package.
 *
 * The one admin-equivalent name is {@see self::Admin} (`credential:admin`): on the
 * operator surfaces it satisfies every ability those routes name, and
 * {@see self::adminEquivalent} is the enforced bound of what that is
 * today. It is the explicit break-glass marking: a credential holding
 * `credential:admin` in its abilities list IS the break-glass credential,
 * deliberately minted with that literal name (the installer's operator
 * credential is one); nothing acquires the equivalence implicitly, and
 * least privilege is the default because minting without abilities grants
 * nothing at all.
 *
 * `credential:admin` deliberately does NOT satisfy the per-tool MCP gates:
 * `mcp:read` and `mcp:admin` are their own grants, checked exact-match by
 * the per-tool primitive ({@see EnsureCredentialAbility}), so an operator
 * break-glass credential cannot silently double as an MCP credential.
 *
 * The MCP pair is SEC-8's least-privilege split: `mcp:read` for read-only
 * MCP tools, `mcp:admin` for destructive administration tools — distinct
 * names, so a credential can hold `mcp:read` without any destructive
 * ability, and enforceable PER TOOL: a consuming app wires
 * `bfc.ability:mcp:read` (or `:mcp:admin`) in front of each MCP tool
 * route. The fail-closed gate half (resolveModel + hasScope, fallback
 * denied) shipped app-side in Phase 0.5a; this vocabulary is the
 * least-privilege half.
 *
 * The pending→active hmac cutover (`activate`) rides the
 * `credential:rotate` FAMILY on the operator surface: activation completes
 * the rotate verb's make-before-break dance, and this vocabulary is
 * per-verb-FAMILY by design. The declaration-level verb matrix
 * ({@see CredentialVerb::Activate}) remains the finer instrument for apps
 * that must split them.
 *
 * Console countersigning-key writes do NOT ride that family, and the
 * boundary is worth stating because it looks like an exception: filing a
 * key is a make-before-break rotation in shape, but what it installs is a
 * standing authority to mint delegated-ADMIN entry into this deployment.
 * Folding it into `credential:rotate` would have handed that power to
 * every rotate-scoped credential already in the field, on upgrade, with
 * no reissue. {@see self::ConsoleKeyWrite} is therefore its own name —
 * the one place this vocabulary splits on BLAST RADIUS rather than on
 * verb family, and it splits deliberately.
 *
 * {@see self::MetadataRead} (`metadata:read`) is the Console's
 * dashboard-read ability, and it is the one name in this vocabulary that
 * `credential:admin` deliberately does NOT reach. It is absent from
 * {@see self::adminEquivalent} on purpose — see that case's docblock for
 * why widening it would defeat the decision it exists to enforce.
 */
enum OperatorAbility: string
{
    /** Explicit break-glass access to the bounded operator surfaces. */
    case Admin = 'credential:admin';

    /** Read the credential listings — an audited sensitive read. */
    case CredentialRead = 'credential:read';

    /** Mint credentials, claim codes, and invitations. */
    case CredentialMint = 'credential:mint';

    /** Rotate credentials, and activate a pending hmac key (same family). */
    case CredentialRotate = 'credential:rotate';

    /** Revoke credentials by id. */
    case CredentialRevoke = 'credential:revoke';

    /** Offboard a subject — full account containment (PRD 1.15). */
    case SubjectOffboard = 'subject:offboard';

    /**
     * Release or cancel deployment ownership. This high-blast-radius verb
     * is not implied by credential mint/revoke or subject offboarding.
     */
    case OwnershipRelease = 'ownership:release';

    /**
     * File a console countersigning key (Console PRD D12) — its OWN
     * name, deliberately not folded into {@see self::CredentialRotate}.
     *
     * A re-key looks like a rotation and was first specified as one.
     * That was wrong, and the reason is upgrade semantics rather than
     * taxonomy: every credential ALREADY ISSUED with `credential:rotate`
     * would have gained Console-admin takeover power the moment this
     * release landed, with no reissue and nobody's decision. A service
     * scoped to rotate ordinary integration credentials would have been
     * able to post its own public key and thereafter mint delegated-ADMIN
     * assertions for the deployment. Silently widening what an issued
     * credential means is the exact failure this per-verb-family
     * vocabulary exists to prevent, and "the verbs are related" does not
     * outrank it.
     *
     * `credential:admin` satisfies it ({@see self::adminEquivalent}) —
     * the break-glass is an explicit, deliberate marking, so widening it
     * widens something an operator chose. `credential:rotate` does not.
     */
    case ConsoleKeyWrite = 'console:key:write';

    /**
     * Read a `metadata`-classified endpoint on behalf of the vendor's
     * Console — today exactly one route,
     * {@see ConsoleVitals} (`GET /bfc/console/vitals`).
     *
     * **Deliberately absent from {@see self::adminEquivalent}, and this
     * is the one case where that absence is load-bearing.** Console PRD
     * D16 names the ability as the ONLY permitted dashboard credential:
     * least-privilege, read-audited, unable to touch content-classified
     * or mutating surfaces, and it explicitly FORBIDS using the
     * ownership/admin credential for any dashboard read path. Putting
     * this name in the admin-equivalent set — the shape
     * {@see self::ConsoleKeyWrite} took one release ago — would have
     * made every break-glass credential a valid dashboard credential and
     * left nothing enforcing D16 at all.
     *
     * The route is mounted behind {@see EnsureDashboardCredential} —
     * alone, with no ability middleware in front of it — which admits only
     * an operator-subject credential
     * whose abilities list is exactly `{metadata:read}`. A credential
     * holding `credential:admin` fails that whether or not it also holds
     * this name, which is what D16's "unable to touch
     * content-classified or mutating surfaces" actually asks for.
     */
    case MetadataRead = 'metadata:read';

    /** Read the audit stream. No package HTTP surface serves it yet; the
     * name is vocabulary so the first audit-read surface enforces it. */
    case AuditRead = 'audit:read';

    /** Invoke read-only MCP tools (SEC-8's narrow ability — what the
     * claim route's minted tokens should carry for MCP use). */
    case McpRead = 'mcp:read';

    /** Invoke destructive MCP administration tools (sink's PurgeTool
     * class of tool). Never implied by any other ability. */
    case McpAdmin = 'mcp:admin';

    /**
     * Every ability reserved to an operator-authority credential.
     *
     * @return list<string>
     */
    public static function vocabulary(): array
    {
        return array_map(
            static fn (self $ability): string => $ability->value,
            self::cases(),
        );
    }

    /**
     * The enforced inventory of what `credential:admin` reaches on the
     * operator surfaces. {@see EnsureCredentialAdmin} consults this exact
     * set, so a future enum ability is not granted until it is deliberately
     * added here. MCP and dashboard metadata remain outside the expansion.
     *
     * @return list<self>
     */
    public static function adminEquivalent(): array
    {
        return [
            self::CredentialRead,
            self::CredentialMint,
            self::CredentialRotate,
            self::CredentialRevoke,
            self::SubjectOffboard,
            self::OwnershipRelease,
            self::AuditRead,
            self::ConsoleKeyWrite,
        ];
    }

    /**
     * @param  list<string>|null  $abilities
     * @return list<string>|null
     */
    public static function parseValues(?array $abilities): ?array
    {
        self::assertValues($abilities);

        return $abilities;
    }

    /** @param list<string>|null $abilities */
    public static function assertValues(?array $abilities): void
    {
        foreach ($abilities ?? [] as $ability) {
            if (self::tryFrom($ability) === null) {
                throw InvalidCredentialInput::unknownAbility($ability);
            }
        }
    }
}
