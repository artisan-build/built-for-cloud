<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\Actions\ListCredentials;
use ArtisanBuild\BuiltForCloud\Actions\MintCredential;
use ArtisanBuild\BuiltForCloud\Actions\RevokeCredential;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialSummary;
use ArtisanBuild\BuiltForCloud\DeliveryShape;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialVerbRefused;
use ArtisanBuild\BuiltForCloud\MintOptions;
use ArtisanBuild\BuiltForCloud\MintResult;
use ArtisanBuild\BuiltForCloud\RevokeOutcome;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
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
        /** @var array{subject_type: string, subject_ref: string, kind?: string|null, name?: string|null, abilities?: list<string>|null, expires_at?: string|null, user_id?: string|null, code_ttl_seconds?: int|null} $validated */
        $validated = $request->validate([
            'subject_type' => ['required', 'string', Rule::in(SubjectType::values())],
            'subject_ref' => ['required', 'string'],
            'kind' => ['nullable', 'string', Rule::in(CredentialKind::values())],
            'name' => ['nullable', 'string'],
            'abilities' => ['nullable', 'array'],
            'abilities.*' => ['string'],
            'expires_at' => ['nullable', 'date'],
            'user_id' => ['nullable', 'string'],
            'code_ttl_seconds' => ['nullable', 'integer', 'between:60,604800'],
        ]);

        $abilities = $validated['abilities'] ?? null;

        try {
            $result = $mint(
                new Subject(SubjectType::from($validated['subject_type']), $validated['subject_ref']),
                new MintOptions(
                    kind: CredentialKind::from($validated['kind'] ?? CredentialKind::Bearer->value),
                    name: $validated['name'] ?? null,
                    abilities: $abilities === null ? null : array_values($abilities),
                    expiresAt: isset($validated['expires_at']) ? Carbon::parse($validated['expires_at']) : null,
                    userId: $validated['user_id'] ?? null,
                    codeTtlSeconds: $validated['code_ttl_seconds'] ?? null,
                ),
                $this->actor($request),
            );
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
            case DeliveryShape::None:
                break;
        }

        return $payload;
    }

    /**
     * D8's actor on the HTTP path: the admin token the gate authenticated,
     * stashed by the middleware. The id, never the credential.
     */
    private function actor(Request $request): ?AuditActor
    {
        $actorId = $request->attributes->get('bfc.actor_token_id');

        return is_string($actorId) && $actorId !== '' ? AuditActor::adminToken($actorId) : null;
    }
}
