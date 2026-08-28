<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Auth;

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\Hmac\HmacVerifier;
use ArtisanBuild\BuiltForCloud\OffboardedSubject;

/**
 * Hash lookup against the unified store. A presented secret resolves only a
 * row of the presenting kind that is active, unrevoked, unexpired and not
 * pending. There is deliberately NO fallback-token path here: the env
 * pseudo-credential is a legacy `TokenRegistry` concern the new guard never
 * consults.
 *
 * THE CONTAINMENT CHOKE POINT (PRD 1.15, SEC-V3-04, rework 3 Fix 1): the
 * offboarded-registry rejection lives HERE, in the one method every
 * unified-store secret resolution flows through — the `bfc` guard's
 * authenticators, `CredentialGuard::validate()`, the operator gate, the
 * onboarding verify surface, and any future caller alike. A credential
 * whose subject — or bound user — is offboarded resolves to NULL
 * everywhere, structurally: a new resolution path cannot forget the check,
 * because it cannot resolve without it. The non-resolution rejection —
 * indistinguishable from an unknown secret — also means no caller ever
 * records a use, first-use-burns a code, or leaks that the principal
 * exists.
 *
 * The ONE credential-authentication path that does not pass through this
 * resolver is {@see HmacVerifier}'s key selection (keys are selected by
 * server-derived subject + key id, never by secret hash); it carries its
 * own registry check for exactly that reason — load-bearing there, not
 * defense-in-depth.
 */
final class CredentialResolver
{
    public function resolve(CredentialKind $kind, ?string $secret): ?Credential
    {
        if ($secret === null || $secret === '') {
            return null;
        }

        /** @var Credential|null $credential */
        $credential = Credential::query()
            ->where('kind', $kind->value)
            ->where('secret_hash', hash('sha256', $secret))
            ->active()
            ->first();

        if ($credential === null || OffboardedSubject::rejects($credential)) {
            return null;
        }

        return $credential;
    }
}
