<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\Actions\DecideDeviceAuthorization;
use ArtisanBuild\BuiltForCloud\Actions\PollDeviceAuthorization;
use ArtisanBuild\BuiltForCloud\Actions\StartDeviceAuthorization;
use ArtisanBuild\BuiltForCloud\BrowserCredentialAuthorizationStore;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationPolicy;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationStatus;
use ArtisanBuild\BuiltForCloud\CredentialVerb;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialAuthorizationRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\Exceptions\SubmissionNonceRefused;
use ArtisanBuild\BuiltForCloud\Http\ClosedRequestInput;
use ArtisanBuild\BuiltForCloud\SubmissionNonce;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use OverflowException;

final class DeviceAuthorizations
{
    public function store(
        Request $request,
        StartDeviceAuthorization $start,
        BrowserCredentialAuthorizationStore $browser,
    ): JsonResponse {
        try {
            $input = ClosedRequestInput::json($request, ['app_purpose'], ['label']);

            if (! is_string($input['app_purpose'])
                || $input['app_purpose'] === ''
                || (isset($input['label']) && ! is_string($input['label']))) {
                throw CredentialAuthorizationRefused::invalidRequest();
            }

            if (! $browser->hasCapacity($request)) {
                throw CredentialAuthorizationRefused::temporarilyUnavailable();
            }

            $result = $start($request, $input['app_purpose'], $input['label'] ?? null);
            $deviceCode = $result->deviceCode->reveal();
            $userCode = $result->userCode->reveal();
            $browserNonce = $result->browserNonce->reveal();
            $browser->putDevice($request, $result->authorizationId, $browserNonce, $userCode);
        } catch (CredentialAuthorizationRefused $refused) {
            return $this->startRefusal($refused);
        } catch (InvalidCredentialInput) {
            return $this->json(['error' => 'access_denied'], 403);
        } catch (OverflowException) {
            return $this->json(['error' => 'temporarily_unavailable'], 503, 5);
        }

        return $this->json([
            'device_code' => $deviceCode,
            'user_code' => $userCode,
            'verification_uri' => $result->verificationUri,
            'expires_in' => $result->expiresIn,
            'interval' => $result->interval,
        ], 201);
    }

    public function show(
        Request $request,
        BrowserCredentialAuthorizationStore $browser,
        CredentialAuthorizationPolicy $policy,
    ): Response {
        if ((string) $request->server->get('QUERY_STRING', '') !== '') {
            return $this->unavailable();
        }

        $authorizations = [];

        foreach ($browser->deviceBindings($request) as $entry) {
            try {
                $policy->revalidate($request, $entry['authorization']);
            } catch (CredentialAuthorizationRefused) {
                continue;
            }

            $authorizations[] = $this->viewAuthorization($request, $entry);
        }

        if ($authorizations === []) {
            return $this->unavailable();
        }

        return $this->view('bfc::authorizations.device', [
            'authorizations' => $authorizations,
            'outcome' => null,
        ]);
    }

    public function decide(
        Request $request,
        DecideDeviceAuthorization $decide,
        BrowserCredentialAuthorizationStore $browser,
    ): Response {
        try {
            $input = ClosedRequestInput::form($request, ['user_code', 'action', SubmissionNonce::FIELD]);
            $userCode = is_string($input['user_code'])
                ? DecideDeviceAuthorization::normalizeUserCode($input['user_code'])
                : throw CredentialAuthorizationRefused::unavailable();
            $action = $input['action'];

            if (! in_array($action, ['approve', 'deny'], true)) {
                throw CredentialAuthorizationRefused::unavailable();
            }

            $entry = $browser->deviceBinding($request, $userCode);

            if ($entry === null) {
                throw CredentialAuthorizationRefused::unavailable();
            }

            $authorizationId = (string) $entry['authorization']->id;
            $submission = SubmissionNonce::presented(
                $input[SubmissionNonce::FIELD],
                $request->session()->getId(),
                $this->userId($request),
                CredentialVerb::Issue,
                $this->target($authorizationId, (string) $action),
            );
            $result = $decide(
                $request,
                $userCode,
                (string) $entry['payload']['browser_nonce'],
                $action === 'approve',
                $submission,
            );
            $browser->forget($request, $authorizationId);
        } catch (SubmissionNonceRefused|CredentialAuthorizationRefused $refused) {
            if ($refused instanceof CredentialAuthorizationRefused && $refused->error === 'temporarily_unavailable') {
                return $this->view('bfc::authorizations.device', [
                    'authorizations' => [],
                    'outcome' => 'retry',
                ], 503, 5);
            }

            return $this->unavailable();
        }

        return $this->view('bfc::authorizations.device', [
            'authorizations' => [],
            'outcome' => $result->status === CredentialAuthorizationStatus::Approved ? 'approved' : 'denied',
        ]);
    }

    public function token(Request $request, PollDeviceAuthorization $poll): JsonResponse
    {
        try {
            $input = ClosedRequestInput::json($request, ['device_code']);

            if (! is_string($input['device_code']) || $input['device_code'] === '' || strlen($input['device_code']) > 128) {
                throw CredentialAuthorizationRefused::invalidRequest();
            }

            $token = $poll($request, $input['device_code']);
        } catch (CredentialAuthorizationRefused $refused) {
            return $this->tokenRefusal($refused);
        }

        $payload = [
            'access_token' => $token->accessToken->reveal(),
            'token_type' => 'Bearer',
            'credential_id' => $token->credentialId,
            'app_purpose' => $token->appPurpose,
        ];

        if ($token->expiresAt !== null) {
            $payload['expires_at'] = $token->expiresAt->toRfc3339String();
        }

        return $this->json($payload);
    }

    /** @param array{payload: array<string, mixed>, authorization: object} $entry @return array<string, mixed> */
    private function viewAuthorization(Request $request, array $entry): array
    {
        $authorization = $entry['authorization'];
        $authorizationId = (string) $authorization->id;
        $sessionId = $request->session()->getId();
        $userId = $this->userId($request);

        return [
            'userCode' => (string) $entry['payload']['user_code'],
            'appPurpose' => (string) $authorization->app_purpose,
            'audience' => (string) $authorization->audience,
            'installation' => (string) $authorization->installation_ref,
            'application' => (string) $authorization->application_ref,
            'ownership' => (string) $authorization->ownership,
            'label' => is_string($authorization->label) ? $authorization->label : null,
            'approveNonce' => SubmissionNonce::issue($sessionId, $userId, CredentialVerb::Issue, $this->target($authorizationId, 'approve')),
            'denyNonce' => SubmissionNonce::issue($sessionId, $userId, CredentialVerb::Issue, $this->target($authorizationId, 'deny')),
        ];
    }

    private function target(string $authorizationId, string $action): string
    {
        return 'device-authorization:'.$authorizationId.':'.$action;
    }

    private function userId(Request $request): string
    {
        $user = $request->user();

        if (! $user instanceof Authenticatable || ! is_scalar($user->getAuthIdentifier())) {
            throw CredentialAuthorizationRefused::unavailable();
        }

        return (string) $user->getAuthIdentifier();
    }

    private function startRefusal(CredentialAuthorizationRefused $refused): JsonResponse
    {
        return match ($refused->error) {
            'temporarily_unavailable' => $this->json(['error' => $refused->error], 503, $refused->retryAfter ?? 5),
            'access_denied' => $this->json(['error' => $refused->error], 403),
            default => $this->json(['error' => 'invalid_request'], 400),
        };
    }

    private function tokenRefusal(CredentialAuthorizationRefused $refused): JsonResponse
    {
        $payload = ['error' => $refused->error];

        if ($refused->interval !== null) {
            $payload['interval'] = $refused->interval;
        }

        return $this->json(
            $payload,
            $refused->error === 'temporarily_unavailable' ? 503 : 400,
            $refused->retryAfter,
        );
    }

    /** @param array<string, mixed> $payload */
    private function json(array $payload, int $status = 200, ?int $retryAfter = null): JsonResponse
    {
        $response = response()->json($payload, $status, $this->headers());

        if ($retryAfter !== null) {
            $response->headers->set('Retry-After', (string) max(1, min(30, $retryAfter)));
        }

        return $response;
    }

    private function unavailable(): Response
    {
        return $this->view('bfc::authorizations.device', [
            'authorizations' => [],
            'outcome' => 'unavailable',
        ], 404);
    }

    /** @param array<string, mixed> $data */
    private function view(string $name, array $data, int $status = 200, ?int $retryAfter = null): Response
    {
        $response = response()->view($name, $data, $status, $this->headers());

        if ($retryAfter !== null) {
            $response->headers->set('Retry-After', (string) $retryAfter);
        }

        return $response;
    }

    /** @return array<string, string> */
    private function headers(): array
    {
        return [
            'Cache-Control' => 'no-store',
            'Pragma' => 'no-cache',
            'Referrer-Policy' => 'no-referrer',
        ];
    }
}
