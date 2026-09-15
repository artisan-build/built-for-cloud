<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\Actions\SourceBoundHmacCutover;
use ArtisanBuild\BuiltForCloud\BoundCredentialScope;
use ArtisanBuild\BuiltForCloud\Exceptions\HmacCredentialTransferRefused;
use ArtisanBuild\BuiltForCloud\IssuerHmacCutoverReceipt;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Throwable;

/** Protected HTTP wire for issuer activation and status recovery. */
final class BoundHmacCutovers extends OperatorRouteController
{
    public function activate(Request $request, SourceBoundHmacCutover $cutover): JsonResponse
    {
        try {
            [$scope, $predecessorId, $replacementId] = $this->input($request, true);
            $fingerprint = $request->input('delivery_fingerprint');

            if (! is_string($fingerprint) || preg_match('/\A[0-9a-f]{16}\z/D', $fingerprint) !== 1) {
                throw new HmacCredentialTransferRefused;
            }

            return $this->response($cutover->activate($scope, $predecessorId, $replacementId, $fingerprint));
        } catch (Throwable) {
            return response()->json(['message' => 'The HMAC cutover was refused.'], 409);
        }
    }

    public function status(Request $request, SourceBoundHmacCutover $cutover): JsonResponse
    {
        try {
            [$scope, $predecessorId, $replacementId] = $this->input($request, false);

            return $this->response($cutover->status($scope, $predecessorId, $replacementId));
        } catch (Throwable) {
            return response()->json(['message' => 'The HMAC cutover was refused.'], 409);
        }
    }

    /** @return array{BoundCredentialScope, string|null, string} */
    private function input(Request $request, bool $activation): array
    {
        $expected = [
            'app_purpose', 'subject_type', 'subject_ref', 'installation_ref', 'application_ref',
            'audience', 'predecessor_credential_id', 'replacement_credential_id',
        ];

        if ($activation) {
            $expected[] = 'delivery_fingerprint';
        }

        $actual = array_keys($request->all());
        sort($actual);
        sort($expected);

        if ($actual !== $expected) {
            throw new HmacCredentialTransferRefused;
        }

        foreach (['app_purpose', 'subject_type', 'subject_ref', 'installation_ref', 'application_ref', 'audience', 'replacement_credential_id'] as $field) {
            if (! is_string($request->input($field))) {
                throw new HmacCredentialTransferRefused;
            }
        }

        $subjectType = SubjectType::tryFrom((string) $request->input('subject_type'));
        $predecessorId = $request->input('predecessor_credential_id');
        $replacementId = (string) $request->input('replacement_credential_id');

        if ($subjectType === null
            || ($predecessorId !== null && (! is_string($predecessorId) || ! Str::isUuid($predecessorId)))
            || ! Str::isUuid($replacementId)) {
            throw new HmacCredentialTransferRefused;
        }

        return [
            new BoundCredentialScope(
                (string) $request->input('app_purpose'),
                new Subject($subjectType, (string) $request->input('subject_ref')),
                (string) $request->input('installation_ref'),
                (string) $request->input('application_ref'),
                (string) $request->input('audience'),
            ),
            $predecessorId,
            $replacementId,
        ];
    }

    private function response(IssuerHmacCutoverReceipt $receipt): JsonResponse
    {
        return response()->json([
            'predecessor_credential_id' => $receipt->predecessorCredentialId,
            'replacement_credential_id' => $receipt->replacementCredentialId,
            'app_purpose' => $receipt->scope->appPurpose,
            'subject_type' => $receipt->scope->subject->type->value,
            'subject_ref' => $receipt->scope->subject->ref,
            'installation_ref' => $receipt->scope->installation,
            'application_ref' => $receipt->scope->application,
            'audience' => $receipt->scope->audience,
            'activated_at' => $receipt->activatedAt->toRfc3339String(),
            'predecessor_expires_at' => $receipt->predecessorExpiresAt?->toRfc3339String(),
            'emergency' => $receipt->emergency,
        ])->header('Cache-Control', 'no-store');
    }
}
