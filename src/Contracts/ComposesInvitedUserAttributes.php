<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Contracts;

use ArtisanBuild\BuiltForCloud\Invitation;

/**
 * The `accept()` attribute-composition hook (PRD 1.13, D4 cost 4): the ONE
 * place an app shapes the user an invitation creates. Capstan projects the
 * invitation's stored `role` onto its user; crate projects
 * key-management-only. Bind an implementation in the container to opt in —
 * an app that binds nothing sees today's behaviour exactly.
 *
 * The hook composes ATTRIBUTES only. It cannot escalate what the package
 * refuses on this path: `is_admin` is stripped from its return before the
 * user is created, and an ADDRESSED invitation's email still overrides
 * whatever the composed attributes carry.
 */
interface ComposesInvitedUserAttributes
{
    /**
     * @param  array<string, mixed>  $attributes  the registrant-supplied attributes, password already hashed
     * @return array<string, mixed> the attributes the user is created with
     */
    public function composeInvitedUserAttributes(Invitation $invitation, array $attributes): array;
}
