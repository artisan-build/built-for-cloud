<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\Actions\ListCredentials;
use ArtisanBuild\BuiltForCloud\Actions\MintCredential;
use ArtisanBuild\BuiltForCloud\Actions\RevokeCredential;
use ArtisanBuild\BuiltForCloud\Actions\RotateCredential;
use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\CredentialManagementScope;
use ArtisanBuild\BuiltForCloud\CredentialSummary;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialVerbRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\Exceptions\RewrapInProgress;
use ArtisanBuild\BuiltForCloud\Exceptions\RotationCutoverIncomplete;
use ArtisanBuild\BuiltForCloud\Exceptions\RotationRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\SigningRootRefused;
use ArtisanBuild\BuiltForCloud\Http\Controllers\Concerns\RevealsDelivery;
use ArtisanBuild\BuiltForCloud\MintOptions;
use ArtisanBuild\BuiltForCloud\RevokeOutcome;
use ArtisanBuild\BuiltForCloud\RolePolicy;
use ArtisanBuild\BuiltForCloud\RotateOptions;
use ArtisanBuild\BuiltForCloud\SelfServiceKindPolicyResolver;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;
use Symfony\Component\HttpFoundation\Response;

/**
 * Session-authenticated management of installation-owned credentials.
 * Issuer attribution is an audit fact; it never scopes who may manage a row.
 */
final class InstallationCredentials
{
    use RevealsDelivery;

    public function index(Request $request, ListCredentials $list): JsonResponse
    {
        $this->actor($request);

        return response()->json([
            'credentials' => array_map(
                static fn (CredentialSummary $summary): array => $summary->toArray(),
                $list(managementScope: CredentialManagementScope::memberInstallation()),
            ),
        ]);
    }

    public function store(
        Request $request,
        MintCredential $mint,
        SelfServiceKindPolicyResolver $kindPolicy,
    ): JsonResponse
    {
        $managementScope = CredentialManagementScope::memberInstallation();

        /** @var array{subject_type: string, subject_ref: string} $validated */
        $validated = $request->validate([
            'subject_type' => ['required', 'string', Rule::in($managementScope->subjectTypes())],
            'subject_ref' => ['required', 'string'],
        ]);

        try {
            $options = MintOptions::fromInput($request->only([
                'kind', 'purpose', 'name', 'abilities', 'expires_at', 'code_ttl_seconds',
            ]));
            $refusedAbility = $managementScope->firstExcludedAbility($options->abilities);

            if ($refusedAbility !== null) {
                throw CredentialVerbRefused::abilityWidening($refusedAbility);
            }

            $subject = new Subject(SubjectType::from($validated['subject_type']), $validated['subject_ref']);
            $kindPolicy->assertInstallationKindAllowed($subject, $options->kind);
            $result = $mint(
                $subject,
                new MintOptions(
                    kind: $options->kind,
                    purpose: $options->purpose,
                    name: $options->name,
                    abilities: $options->abilities,
                    expiresAt: $options->expiresAt,
                    userId: null,
                    codeTtlSeconds: $options->codeTtlSeconds,
                ),
                $this->actor($request),
            );
        } catch (InvalidCredentialInput $invalid) {
            return response()->json(['message' => $invalid->getMessage()], 422);
        } catch (CredentialVerbRefused $refused) {
            return response()->json(['message' => $refused->getMessage()], 403);
        } catch (RewrapInProgress $refused) {
            return response()->json(['message' => $refused->getMessage()], 409);
        }

        return response()->json([
            'credential' => $result->summary->toArray(),
            'delivery' => $this->deliveryPayload($result),
        ], 201);
    }

    public function rotate(Request $request, RotateCredential $rotate, string $id): JsonResponse
    {
        try {
            $result = $rotate(
                $id,
                RotateOptions::fromInput($request->only([
                    'emergency', 'override', 'abilities', 'expires_at', 'code_ttl_seconds',
                ])),
                $this->actor($request),
                CredentialManagementScope::memberInstallation(),
            );
        } catch (InvalidCredentialInput $invalid) {
            return response()->json(['message' => $invalid->getMessage()], 422);
        } catch (CredentialVerbRefused $refused) {
            return response()->json(['message' => $refused->getMessage()], 403);
        } catch (RotationRefused|RewrapInProgress|SigningRootRefused $refused) {
            return response()->json(['message' => $refused->getMessage()], 409);
        } catch (RotationCutoverIncomplete $incomplete) {
            return response()->json(['message' => $incomplete->getMessage()], 500);
        }

        if ($result === null) {
            abort(404);
        }

        return response()->json([
            'credential' => $result->mint->summary->toArray(),
            'superseded_id' => $result->supersededId,
            'delivery' => $this->deliveryPayload($result->mint),
        ] + ($result->completedCutover ? ['completed_cutover' => true] : []), $result->completedCutover ? 200 : 201);
    }

    public function destroy(Request $request, RevokeCredential $revoke, string $id): Response
    {
        try {
            $outcome = $revoke(
                $id,
                $this->actor($request),
                managementScope: CredentialManagementScope::memberInstallation(),
            );
        } catch (CredentialVerbRefused $refused) {
            return response()->json(['message' => $refused->getMessage()], 403);
        }

        return match ($outcome) {
            RevokeOutcome::NotFound => abort(404),
            RevokeOutcome::Revoked, RevokeOutcome::AlreadyDead => response()->noContent(),
        };
    }

    private function actor(Request $request): AuditActor
    {
        $user = $request->user();

        if (! $user instanceof User || ! RolePolicy::canManageInstallationCredentials($user->role)) {
            abort(403);
        }

        return AuditActor::boundUser((string) $user->getAuthIdentifier());
    }
}
