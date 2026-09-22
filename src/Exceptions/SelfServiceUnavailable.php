<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Exceptions;

use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\PersonalCredentialSurface;
use RuntimeException;

/**
 * The personal-credentials surface (PRD 1.17) has nothing to act for: the
 * app's declaration resolved NO subject from this authenticated request
 * ({@see CredentialDeclaration::resolveSubject()} returned null).
 *
 * This is the fail-closed answer, deliberately. The subject is derived
 * server-side and only there (SEC-V3-07), so "no subject" is not "no
 * credentials" — it means this app has not declared what an authenticated
 * human's credentials are FOR, and the surface must not invent one from
 * anything the caller sent. An empty listing would read as "you hold
 * none", which is a different and false claim.
 *
 * Thrown by {@see PersonalCredentialSurface}, so a UI consumer refuses
 * identically to the HTTP transport (which maps it to a 403).
 */
final class SelfServiceUnavailable extends RuntimeException
{
    public static function noResolvableSubject(): self
    {
        return new self(
            'This application declares no personal-credential subject for the authenticated session, '
            .'so there is nothing this surface can list, mint or revoke.',
        );
    }

    public static function noLocalUserIdentifier(): self
    {
        return new self('The authenticated session has no usable local user identifier, so the personal-credentials surface refuses it.');
    }

    /**
     * A DELEGATED actor is on this request, and this surface can only
     * act as the authenticated local human.
     *
     * Refusing is the whole point rather than a limitation. A delegated
     * operator has no personal credentials in this application, and
     * falling through to the local session user would mean minting or
     * revoking a local human's personal credentials while somebody else
     * is at the keyboard — exactly the principal/surface disagreement
     * the resolved-value rule exists to forbid. There is no honest
     * identity to substitute, so the surface says so.
     */
    public static function delegatedPrincipal(): self
    {
        return new self(
            'A delegated actor has no personal identity in this application, '
            .'so the personal-credentials surface refuses it rather than acting as the local session user.',
        );
    }
}
