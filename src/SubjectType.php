<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Contracts\AuthorizesCredentialVerbs;

/**
 * What one revocation costs. A subject type describes the blast radius of
 * killing a credential; it never grants anything by itself — authority is
 * a separate, explicit, per-verb declaration
 * ({@see AuthorizesCredentialVerbs}),
 * and no permission is ever inferred from a subject type, a `subject_ref`,
 * or possession of a name (PRD 1.4, D2).
 *
 * D2's cost-of-revocation semantics — what a fleet screen renders per type:
 *
 * | subject_type        | what one revocation costs                          |
 * |---------------------|----------------------------------------------------|
 * | `application`       | a whole application stops reporting                |
 * | `installation`      | one enrolled install of one application; sibling installs survive |
 * | `user_principal`    | one authenticated user's own credential; they hold a session and can revoke it themselves |
 * | `external_consumer` | one outside party — a person, a CI runner, or a client system — is cut off; siblings keep working |
 * | `operator`          | a control plane loses management access; the app itself keeps running. Multiple may coexist per instance, each its own audit actor, each revocable alone |
 */
enum SubjectType: string
{
    case Application = 'application';
    case Installation = 'installation';
    case UserPrincipal = 'user_principal';
    case ExternalConsumer = 'external_consumer';
    case Operator = 'operator';

    /**
     * @return array<int, string>
     */
    public static function values(): array
    {
        return array_map(
            static fn (self $type): string => $type->value,
            self::cases(),
        );
    }
}
