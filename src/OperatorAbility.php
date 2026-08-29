<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAbility;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin;

/**
 * The per-verb-family operator ability vocabulary (PRD 1.10 + GATE-3.7,
 * SEC-8, SEC-V3-06). A credential's `abilities` list names EXACTLY what it
 * may do; a null or empty list grants nothing (fails closed, {@see
 * Credential::hasAbility}), and there is NO wildcard value — `*` is not an
 * ability and matches nothing anywhere in the package.
 *
 * The one admin-equivalent name is {@see self::ADMIN} (`credential:admin`,
 * shipped in PRD 1.20 as {@see EnsureCredentialAdmin::ABILITY}): on the
 * operator surfaces it satisfies every ability in
 * {@see self::adminEquivalent} — that set, exactly, is the documented
 * mapping. It is the explicit break-glass marking: a credential holding
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
 * RESERVED, documented and unenforced ({@see self::RESERVED_METADATA_READ},
 * per the Console reservations): the `metadata:read` ability family —
 * least-privilege, read-audited, for future vendor-side reads of
 * `metadata`-classified endpoints. No credential is issued with it and
 * nothing enforces it in this release.
 */
enum OperatorAbility: string
{
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
     * The admin-equivalent break-glass ability
     * ({@see EnsureCredentialAdmin::ABILITY} — one name, asserted equal in
     * the test suite). Holding it satisfies {@see self::adminEquivalent}
     * on the operator surfaces.
     */
    public const string ADMIN = 'credential:admin';

    /**
     * Reserved name only (Console fast-follow): documented in the
     * vocabulary so nothing else claims it; no issuance, no enforcement.
     */
    public const string RESERVED_METADATA_READ = 'metadata:read';

    /**
     * The documented mapping of `credential:admin`: the exact set the
     * break-glass ability expands to on the operator surfaces. The MCP
     * abilities are deliberately absent.
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
            self::AuditRead,
            self::ConsoleKeyWrite,
        ];
    }
}
