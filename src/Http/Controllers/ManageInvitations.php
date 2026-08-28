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
 * Two documented responses, each keyed on the REQUEST, never on state:
 *
 * - the HUMAN path (no integration event) always issues and always
 *   answers `201` with the single reveal — shape-identical for a fresh
 *   subject, a re-invite, and a subject who already accepted;
 * - the INTEGRATION path always answers the uniform `202 {"accepted":
 *   true}` acknowledgement, whatever the gate decided
 *   (applied/ignored/replayed) — no invitation data, so even an
 *   authorized caller cannot probe gate state from the body. Delivery to
 *   an addressed invitee is the post-commit mail; response TIMING remains
 *   a best-effort side channel (an applying event does more work) and is
 *   documented as such.
 */
final class ManageInvitations
{
    public function store(Request $request, IssueInvitation $issue): JsonResponse
    {
        try {
            $options = InvitationOptions::fromInput($request->only([
                'email', 'ttl_seconds', 'invited_by', 'role',
                'integration_namespace', 'event_id', 'entitlement_version', 'external_subject',
            ]));

            $result = $issue($options, $this->actor($request));
        } catch (InvalidCredentialInput $invalid) {
            return response()->json(['message' => $invalid->getMessage()], 422);
        } catch (CredentialVerbRefused $refused) {
            return response()->json(['message' => $refused->getMessage()], 403);
        }

        // A partial group already threw, so a complete group here IS the
        // integration path: one uniform acknowledgement, nothing revealed.
        if ($options->integrationEventComplete()) {
            return response()->json(['accepted' => true], 202);
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
