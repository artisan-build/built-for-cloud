<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\Actions\CompleteAsymmetricEnrollment;
use ArtisanBuild\BuiltForCloud\Contracts\ResolvesAsymmetricEnrollmentScope;
use ArtisanBuild\BuiltForCloud\Exceptions\AsymmetricEnrollmentUnavailable;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\Rs256PublicKey;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Throwable;

final class AsymmetricEnrollments
{
    public const int MAX_BODY_BYTES = 24576;

    public function __invoke(
        Request $request,
        string $application,
        ResolvesAsymmetricEnrollmentScope $scopes,
        CompleteAsymmetricEnrollment $complete,
    ): JsonResponse {
        if (strlen($request->getContent()) > self::MAX_BODY_BYTES) {
            return $this->invalid();
        }

        try {
            $input = $request->json()->all();
        } catch (Throwable) {
            return $this->invalid();
        }

        $keys = array_keys($input);
        sort($keys);

        if ($keys !== ['enrollment_code', 'public_key']
            || ! is_string($input['enrollment_code'] ?? null)
            || preg_match('/\A[0-9a-f]{64}\z/D', $input['enrollment_code']) !== 1
            || ! is_string($input['public_key'] ?? null)
            || strlen($input['public_key']) > Rs256PublicKey::MAX_BYTES) {
            return $this->invalid();
        }

        try {
            $key = new Rs256PublicKey($input['public_key']);
            $scope = $scopes->resolve($request, $application);

            if ($scope === null) {
                throw new AsymmetricEnrollmentUnavailable;
            }

            $enrolled = $complete($input['enrollment_code'], $scope, $key);
        } catch (InvalidCredentialInput $invalid) {
            return response()->json(['message' => $invalid->getMessage()], 422);
        } catch (AsymmetricEnrollmentUnavailable $unavailable) {
            return response()->json(['message' => $unavailable->getMessage()], 404);
        } catch (Throwable $exception) {
            try {
                Log::warning('Built for Cloud could not complete an asymmetric enrollment.', [
                    'exception' => $exception::class,
                ]);
            } catch (Throwable) {
                // Logging cannot replace the bounded response.
            }

            return response()->json(['message' => 'The server hit an unexpected error. It is safe to retry.'], 500);
        }

        return response()->json([
            'credential_id' => $enrolled->credentialId,
            'algorithm' => $enrolled->algorithm->value,
        ], 201)->header('Cache-Control', 'no-store');
    }

    private function invalid(): JsonResponse
    {
        return response()->json(['message' => 'The asymmetric enrollment request is invalid.'], 422);
    }
}
