<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\Actions\IssueInvitation;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialVerbRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\InvitationOptions;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * The invite verb's HTTP transport (PRD 1.13, SEC-V3-05): the SAME
 * {@see IssueInvitation} action the `--local` CLI runs, behind the
 * credential-admin gate. This controller only translates HTTP in and out;
 * every authority and gate answer lives inside the action.
 *
 * The response is ONE non-enumerating shape whatever the prior state:
 * always 201, always the same three keys, with nulls when the version
 * gate acknowledged-and-ignored the event or replayed a known event id —
 * never an invited/active/not-found distinction to probe.
 */
final class ManageInvitations
{
    public function store(Request $request, IssueInvitation $issue): JsonResponse
    {
        try {
            $result = $issue(
                InvitationOptions::fromInput($request->only([
                    'email', 'ttl_seconds', 'invited_by', 'role',
                    'integration_namespace', 'event_id', 'entitlement_version', 'external_subject',
                ])),
                $this->actor($request),
            );
        } catch (InvalidCredentialInput $invalid) {
            return response()->json(['message' => $invalid->getMessage()], 422);
        } catch (CredentialVerbRefused $refused) {
            return response()->json(['message' => $refused->getMessage()], 403);
        }

        return response()->json([
            'invitation_id' => $result->invitationId,
            // The transport boundary: the ONE reveal (D7). The sealed
            // carrier throws on any later call, so a second egress of the
            // same code is structurally impossible.
            'invitation_code' => $result->code?->reveal(),
            'email' => $result->email,
        ], 201);
    }

    /**
     * D8's actor, exactly as on the credential verb routes: the store that
     * authenticated decides the actor type; the id, never the credential.
     */
    private function actor(Request $request): ?AuditActor
    {
        $tokenId = $request->attributes->get('bfc.actor_token_id');

        if (is_string($tokenId) && $tokenId !== '') {
            return AuditActor::adminToken($tokenId);
        }

        $credentialId = $request->attributes->get('bfc.actor_credential_id');

        return is_string($credentialId) && $credentialId !== '' ? AuditActor::operatorIntegration($credentialId) : null;
    }
}
