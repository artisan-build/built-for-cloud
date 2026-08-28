<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Contracts;

use ArtisanBuild\BuiltForCloud\Subject;

/**
 * Opt-in extension of {@see CredentialDeclaration} — the mint ceilings the
 * unified mint verb refuses to widen past (PRD 1.6, locked AC: "mint()
 * refuses ability/lifetime WIDENING beyond what the declaration
 * authorizes"). The established parallel-contract idiom
 * ({@see DeclaresBurnMode}, {@see AuthorizesCredentialVerbs}): existing
 * declarations keep compiling, and not implementing this declares NO
 * ceiling — the verb matrix and the admin gate remain the only authority
 * answer.
 *
 * Both hooks are consulted by the ONE mint action, so CLI `--local` and
 * HTTP refuse identically — a ceiling that only one transport enforced
 * would not be a ceiling.
 */
interface ConstrainsMintedCredentials
{
    /**
     * The abilities mintable for this subject. Null declares no ceiling; a
     * list refuses any mint requesting an ability outside it. An empty
     * list refuses every ability grant.
     *
     * @return list<string>|null
     */
    public function grantableAbilities(Subject $subject): ?array;

    /**
     * The longest lifetime mintable for this subject, in seconds. Null
     * declares no ceiling. When a ceiling is declared, a mint requesting
     * a LATER expiry — or NO expiry at all, which outlives any ceiling —
     * is refused. The package never quietly stamps a shorter expiry
     * instead: TTL defaults on durables are a DO-NOT-BUILD.
     */
    public function maxCredentialLifetimeSeconds(Subject $subject): ?int;
}
