<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Contracts;

use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageCredentials;
use ArtisanBuild\BuiltForCloud\PersonalCredentialSurface;
use ArtisanBuild\BuiltForCloud\Subject;

/**
 * Opt-in extension of {@see CredentialDeclaration}: what a SELF-SERVICE
 * mint may produce (PRD 1.17, rework Fix 2).
 *
 * The two mint paths derive authority from different places, and the
 * difference is the whole point:
 *
 * - the OPERATOR mint ({@see ManageCredentials})
 *   derives it from an ADMIN — an authenticated operator chose the
 *   abilities, and the declaration's optional ceilings
 *   ({@see ConstrainsMintedCredentials}) only NARROW that choice;
 * - the SELF-SERVICE mint ({@see PersonalCredentialSurface}) derives it
 *   from THIS policy, and never from the requesting user's input. A
 *   logged-in human asking for `["mcp:admin"]` is not an authorization,
 *   it is a request, and the surface does not read it.
 *
 * So the self-service path FAILS CLOSED. Absent this contract a
 * self-service credential is minted with **no abilities at all** and in
 * the `bearer` kind only: it can authenticate as its holder and holds no
 * operator, MCP or signing power. An app widens that by declaring, per
 * subject, exactly what its own users may mint for themselves.
 *
 * What is deliberately NOT constrained here is the LIFETIME. A durable's
 * expiry stays caller-chosen with no default (PRD 1.3 / D1b — TTL
 * defaults on durables are a DO-NOT-BUILD); abilities are the escalation
 * vector, and abilities are what fails closed. An app that does want a
 * lifetime ceiling declares one through {@see ConstrainsMintedCredentials},
 * which the mint verb applies to both paths alike.
 */
interface DeclaresSelfServiceMintPolicy
{
    /**
     * The abilities a self-service mint grants this subject — the WHOLE
     * grant, not a ceiling to be filtered against client input. An empty
     * list means the credential holds none.
     *
     * @return list<string>
     */
    public function selfServiceAbilities(Subject $subject): array;

    /**
     * The credential kinds a self-service mint may produce for this
     * subject. A requested kind outside this list is refused; an empty
     * list refuses every self-service mint.
     *
     * @return list<CredentialKind>
     */
    public function selfServiceKinds(Subject $subject): array;
}
