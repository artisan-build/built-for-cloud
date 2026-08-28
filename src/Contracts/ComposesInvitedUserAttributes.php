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
 * The hook is TRUSTED APPLICATION CODE: whoever binds it can shape the
 * created user however the user model allows, so binding one is a
 * privileged act. The package applies two guard-rails to its return —
 * `is_admin` is stripped before the user is created, and an ADDRESSED
 * invitation's email still overrides — as protection against accidental
 * pass-through of registrant input, NOT as a privilege boundary against
 * the hook itself (a hook can reach the same model directly).
 */
interface ComposesInvitedUserAttributes
{
    /**
     * @param  array<string, mixed>  $attributes  the registrant-supplied attributes, password already hashed
     * @return array<string, mixed> the attributes the user is created with
     */
    public function composeInvitedUserAttributes(Invitation $invitation, array $attributes): array;
}
