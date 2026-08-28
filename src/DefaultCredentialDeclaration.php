<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Contracts\AuthorizesCredentialVerbs;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresBurnMode;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresHolderResolution;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresPresentationCadence;
use Illuminate\Http\Request;

/**
 * The declaration the package ships so it works out of the box: no subject
 * derivation, authorization defers entirely to the credential's own
 * lifecycle and abilities (which the guard and middleware already enforce),
 * every verb defers to the gates the same way, claim codes burn on first
 * use — the `api_tokens` provider's mode — holder notifications resolve to
 * NOBODY, and no presentation cadence is declared.
 */
final class DefaultCredentialDeclaration implements AuthorizesCredentialVerbs, CredentialDeclaration, DeclaresBurnMode, DeclaresHolderResolution, DeclaresPresentationCadence
{
    public function burnMode(): BurnMode
    {
        return BurnMode::FirstUse;
    }

    /**
     * NOBODY, deliberately: the default store binds credentials to no
     * person, and an unbound subject notifies no one — there is no
     * operator fallback to spam (PRD 1.16).
     */
    public function resolveHolderEmail(string $credentialId): ?string
    {
        return null;
    }

    public function resolveSubject(Request $request): ?Subject
    {
        return null;
    }

    public function authorize(Credential $credential, ?string $ability, Request $request): bool
    {
        return true;
    }

    /**
     * Every verb is an operator-scope action the admin-token gate (and the
     * guard + abilities middleware) already enforces; the default matrix
     * narrows nothing further. Allowing here never WIDENS anything — the
     * gates are checked before this hook is consulted.
     */
    public function authorizeVerb(CredentialVerb $verb, ?Subject $subject, Request $request): bool
    {
        return true;
    }

    /**
     * NO cadence declared, deliberately (declare-don't-guess): the package
     * cannot know whether a consuming app's credentials are presented per
     * request or per weekly deploy. Null leaves the consuming control
     * plane's own default in charge — exactly today's behaviour. An app
     * that knows its rhythm declares it by overriding this.
     */
    public function presentationCadenceSeconds(): ?int
    {
        return null;
    }
}
