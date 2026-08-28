<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\Actions\ActivateCredential;
use ArtisanBuild\BuiltForCloud\Actions\ListCredentials;
use ArtisanBuild\BuiltForCloud\Actions\MintCredential;
use ArtisanBuild\BuiltForCloud\Actions\RevokeCredential;
use ArtisanBuild\BuiltForCloud\Actions\RotateCredential;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\CredentialSummary;
use ArtisanBuild\BuiltForCloud\DeliveryShape;
use ArtisanBuild\BuiltForCloud\Exceptions\ActivationRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialVerbRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\Exceptions\RewrapInProgress;
use ArtisanBuild\BuiltForCloud\Exceptions\RotationCutoverIncomplete;
use ArtisanBuild\BuiltForCloud\Exceptions\RotationRefused;
use ArtisanBuild\BuiltForCloud\MintOptions;
use ArtisanBuild\BuiltForCloud\MintResult;
use ArtisanBuild\BuiltForCloud\RevokeOutcome;
use ArtisanBuild\BuiltForCloud\RotateOptions;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;
use Symfony\Component\HttpFoundation\Response;

/**
 * The unified store's HTTP transport (PRD 1.0 + 1.6): the SAME action
 * classes the `--local` CLI runs, behind the admin-token gate at a fixed
 * `/bfc/credentials` path. Neither transport can do anything the other
 * cannot — every authority answer (verb matrix, mint ceilings,
 * declared-unsupported fields) lives inside the actions, so this
 * controller only translates HTTP in and out.
 *
 * These routes are part of the versioned public contract
 * (docs/http-contract.md); the legacy `api_tokens` credential API
 * (`/api/credentials`) is a separate, unchanged surface.
 */
final class ManageCredentials
{
    public const CADENCE_HEADER = 'BFC-Presentation-Cadence';

    public function index(ListCredentials $list): JsonResponse
    {
        $summaries = $list();

        $response = response()->json(array_map(
            static fn (CredentialSummary $summary): array => $summary->toArray(),
            $summaries,
        ));

        // The declared cadence rides per row already; the header states it
        // once per listing, matching the legacy listing's convention.
        $cadence = $summaries === [] ? null : $summaries[0]->presentationCadenceSeconds;

        if ($cadence !== null) {
            $response->header(self::CADENCE_HEADER, (string) $cadence);
        }

        return $response;
    }

    public function store(Request $request, MintCredential $mint): JsonResponse
    {
        // Only the subject pair is validated here (it shapes the Subject
        // argument); everything else is normalized by the SHARED input
        // object and the action, so this transport rejects exactly what
        // the CLI rejects (Fix 4) — with the same message, as a 422.
        /** @var array{subject_type: string, subject_ref: string} $validated */
        $validated = $request->validate([
            'subject_type' => ['required', 'string', Rule::in(SubjectType::values())],
            'subject_ref' => ['required', 'string'],
        ]);

        try {
            $result = $mint(
                new Subject(SubjectType::from($validated['subject_type']), $validated['subject_ref']),
                MintOptions::fromInput($request->only([
                    'kind', 'name', 'abilities', 'expires_at', 'user_id', 'code_ttl_seconds',
                ])),
                $this->actor($request),
            );
        } catch (InvalidCredentialInput $invalid) {
            return response()->json(['message' => $invalid->getMessage()], 422);
        } catch (CredentialVerbRefused $refused) {
            return response()->json(['message' => $refused->getMessage()], 403);
        }

        return response()->json([
            'credential' => $result->summary->toArray(),
            // The transport boundary: the ONE reveal (D7). The carrier
            // throws on any later call, so a second egress of the same
            // secret is structurally impossible.
            'delivery' => $this->deliveryPayload($result),
        ], 201);
    }

    /**
     * The rotate verb's HTTP transport (PRD 1.7): by id — the primary
     * verb; there is no name path over HTTP. The response carries the
     * replacement's summary, the superseded row's id (the lineage the
     * audit stream records as old → new), and the single reveal.
     *
     * Failure path B surfaces here as a 500 whose message names the
     * still-live old row: the replacement stands but no secret was
     * delivered, so the caller revokes by id and retries.
     */
    public function rotate(Request $request, RotateCredential $rotateCredential, string $id): JsonResponse
    {
        try {
            $result = $rotateCredential(
                $id,
                RotateOptions::fromInput($request->only([
                    'emergency', 'override', 'abilities', 'expires_at', 'code_ttl_seconds',
                ])),
                $this->actor($request),
            );
        } catch (InvalidCredentialInput $invalid) {
            return response()->json(['message' => $invalid->getMessage()], 422);
        } catch (CredentialVerbRefused $refused) {
            return response()->json(['message' => $refused->getMessage()], 403);
        } catch (RotationRefused|RewrapInProgress $refused) {
            return response()->json(['message' => $refused->getMessage()], 409);
        } catch (RotationCutoverIncomplete $incomplete) {
            return response()->json(['message' => $incomplete->getMessage()], 500);
        }

        if ($result === null) {
            abort(404);
        }

        // The completion path created nothing: 200, the standing successor
        // as `credential`, and a `none` delivery — there is no secret.
        return response()->json([
            'credential' => $result->mint->summary->toArray(),
            'superseded_id' => $result->supersededId,
            // The transport boundary: the ONE reveal (D7), same carrier
            // rule as the mint route.
            'delivery' => $this->deliveryPayload($result->mint),
        ] + ($result->completedCutover ? ['completed_cutover' => true] : []), $result->completedCutover ? 200 : 201);
    }

    /**
     * The activate verb's HTTP transport (PRD 1.21, SEC-V3-01): the hmac
     * pending→active signing cutover, by id. The response carries NO
     * secret — activation reveals nothing; the key was already delivered
     * — just the now-active summary and, when the activation completed a
     * rotation, the superseded row now living out its grace window.
     */
    public function activate(Request $request, ActivateCredential $activateCredential, string $id): JsonResponse
    {
        try {
            $result = $activateCredential($id, $this->actor($request));
        } catch (CredentialVerbRefused $refused) {
            return response()->json(['message' => $refused->getMessage()], 403);
        } catch (ActivationRefused|RewrapInProgress $refused) {
            return response()->json(['message' => $refused->getMessage()], 409);
        } catch (RotationCutoverIncomplete $incomplete) {
            return response()->json(['message' => $incomplete->getMessage()], 500);
        }

        if ($result === null) {
            abort(404);
        }

        return response()->json([
            'credential' => $result->summary->toArray(),
            'superseded_id' => $result->supersededId,
            'grace_ends_at' => $result->graceEndsAt?->toIso8601String(),
        ]);
    }

    public function destroy(Request $request, RevokeCredential $revoke, string $id): Response
    {
        try {
            $outcome = $revoke($id, $this->actor($request));
        } catch (CredentialVerbRefused $refused) {
            return response()->json(['message' => $refused->getMessage()], 403);
        }

        return match ($outcome) {
            RevokeOutcome::NotFound => abort(404),
            // Idempotently 204 for a row already dead — one death, one
            // audit event — matching the legacy by-id verb's semantics.
            RevokeOutcome::Revoked, RevokeOutcome::AlreadyDead => response()->noContent(),
        };
    }

    /**
     * @return array<string, string>
     */
    private function deliveryPayload(MintResult $result): array
    {
        $payload = ['shape' => $result->delivery->value];

        switch ($result->delivery) {
            case DeliveryShape::Bearer:
                if ($result->secret !== null) {
                    $payload['secret'] = $result->secret->reveal();
                }
                break;
            case DeliveryShape::BasicAuth:
                $payload['username'] = (string) $result->basicUsername;

                if ($result->secret !== null) {
                    $payload['password'] = $result->secret->reveal();
                }
                break;
            case DeliveryShape::EnrollmentCode:
                if ($result->secret !== null) {
                    $payload['enrollment_code'] = $result->secret->reveal();
                }
                break;
            case DeliveryShape::SigningKey:
                // The key id rides beside the key (non-secret — the row id
                // the signature header will carry); the key itself is
                // PENDING until the activation verb cuts it over.
                $payload['key_id'] = $result->summary->id;

                if ($result->secret !== null) {
                    $payload['signing_key'] = $result->secret->reveal();
                }
                break;
            case DeliveryShape::SigningKeyCode:
                if ($result->secret !== null) {
                    $payload['claim_code'] = $result->secret->reveal();
                }
                break;
            case DeliveryShape::None:
                break;
        }

        return $payload;
    }

    /**
     * D8's actor on the HTTP path, reflecting WHICH STORE authenticated:
     * a legacy admin `api_tokens` row audits as an `admin_token` actor, a
     * unified-store operator credential as an `operator_integration`
     * actor. The id, never the credential.
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
