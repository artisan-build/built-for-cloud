<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\Actions\OffboardSubject;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialVerbRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\IntegrationEventContention;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\OffboardOptions;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * The offboard verb's HTTP transport (PRD 1.15, SEC-V3-04): the SAME
 * {@see OffboardSubject} action `bfc:subject:offboard --local` runs,
 * behind the operator gate's `subject:offboard` ability. Two documented
 * responses, keyed on the REQUEST, never on state (the invite verb's
 * uniformity rule): the direct path answers `200 {"offboarded": true}` —
 * identical for a first containment and an idempotent repeat — and the
 * integration path answers the uniform `202 {"accepted": true}` whatever
 * the version gate decided.
 */
final class ManageSubjects
{
    public function offboard(Request $request, OffboardSubject $offboardSubject): JsonResponse
    {
        try {
            $options = OffboardOptions::fromInput($request->only([
                'subject_type', 'subject_ref',
                'integration_namespace', 'event_id', 'entitlement_version', 'external_subject',
            ]));

            $result = $offboardSubject($options, $this->actor($request));
        } catch (InvalidCredentialInput $invalid) {
            return response()->json(['message' => $invalid->getMessage()], 422);
        } catch (CredentialVerbRefused $refused) {
            return response()->json(['message' => $refused->getMessage()], 403);
        } catch (IntegrationEventContention $contention) {
            return response()->json(['message' => $contention->getMessage()], 500);
        }

        if ($result->acknowledged) {
            return response()->json(['accepted' => true], 202);
        }

        // `fully_contained` is the honest report (rework Fix 3): false
        // when a containment step could not complete inside the offboard
        // transaction (an unreachable or deferred session store). The
        // registry rejection holds either way; the caller re-runs the
        // idempotent verb after fixing the store. Bounded booleans only —
        // the endpoint stays `metadata`-classified.
        return response()->json([
            'offboarded' => true,
            'fully_contained' => $result->fullyContained(),
        ]);
    }

    /**
     * D8's actor, exactly as on the credential verb routes: the store
     * that authenticated decides the actor type; the id, never the
     * credential.
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
