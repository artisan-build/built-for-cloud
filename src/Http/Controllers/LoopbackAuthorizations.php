<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\Actions\DecideLoopbackAuthorization;
use ArtisanBuild\BuiltForCloud\Actions\ExchangeLoopbackAuthorization;
use ArtisanBuild\BuiltForCloud\Actions\StartLoopbackAuthorization;
use ArtisanBuild\BuiltForCloud\BrowserCredentialAuthorizationStore;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationPolicy;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationStatus;
use ArtisanBuild\BuiltForCloud\CredentialVerb;
use ArtisanBuild\BuiltForCloud\Exceptions\CredentialAuthorizationRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\Exceptions\SubmissionNonceRefused;
use ArtisanBuild\BuiltForCloud\Http\ClosedRequestInput;
use ArtisanBuild\BuiltForCloud\LoopbackRedirectUri;
use ArtisanBuild\BuiltForCloud\SubmissionNonce;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use OverflowException;

final class LoopbackAuthorizations
{
    public function show(
        Request $request,
        StartLoopbackAuthorization $start,
        BrowserCredentialAuthorizationStore $browser,
        CredentialAuthorizationPolicy $policy,
    ): Response {
        try {
            $input = ClosedRequestInput::query(
                $request,
                ['app_purpose', 'redirect_uri', 'code_challenge', 'code_challenge_method', 'state'],
                ['label'],
            );

            foreach (['app_purpose', 'redirect_uri', 'code_challenge', 'code_challenge_method', 'state'] as $field) {
                if (! is_string($input[$field]) || $input[$field] === '') {
                    throw CredentialAuthorizationRefused::invalidRequest();
                }
            }

            $tuple = [
                'app_purpose' => $input['app_purpose'],
                'redirect_uri' => $input['redirect_uri'],
                'code_challenge' => $input['code_challenge'],
                'state' => $input['state'],
                'label' => isset($input['label']) && $input['label'] !== '' ? $input['label'] : null,
            ];
            $entry = $browser->loopbackBinding($request, $tuple);

            if ($entry === null) {
                if (! $browser->hasCapacity($request)) {
                    return $this->unavailable();
                }

                $intent = $start(
                    $request,
                    $tuple['app_purpose'],
                    $tuple['redirect_uri'],
                    $tuple['code_challenge'],
                    $input['code_challenge_method'],
                    $tuple['state'],
                    $tuple['label'],
                );
                $browser->putLoopback($request, $intent->authorizationId, $intent->browserNonce->reveal(), $tuple['state']);
                $entry = $browser->selectedLoopbackBinding($request);
            }

            if ($entry === null) {
                return $this->unavailable();
            }

            $policy->revalidate($request, $entry['authorization']);

            return $this->consent($request, $entry);
        } catch (CredentialAuthorizationRefused|InvalidCredentialInput|OverflowException) {
            return $this->unavailable();
        }
    }

    public function decide(
        Request $request,
        DecideLoopbackAuthorization $decide,
        BrowserCredentialAuthorizationStore $browser,
    ): Response|RedirectResponse {
        $authorizationId = null;

        try {
            $input = ClosedRequestInput::form($request, ['action', SubmissionNonce::FIELD]);
            $action = $input['action'];

            if (! in_array($action, ['approve', 'deny'], true)) {
                throw CredentialAuthorizationRefused::unavailable();
            }

            $entry = $browser->selectedLoopbackBinding($request);

            if ($entry === null) {
                throw CredentialAuthorizationRefused::unavailable();
            }

            $payload = $entry['payload'];
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
                $authorizationId,
                (string) $payload['browser_nonce'],
                (string) $payload['state'],
                $action === 'approve',
                $submission,
            );
            $browser->forget($request, $authorizationId);
        } catch (SubmissionNonceRefused|CredentialAuthorizationRefused $refused) {
            if ($refused instanceof CredentialAuthorizationRefused && $refused->error === 'temporarily_unavailable') {
                return $this->view(['authorization' => null, 'outcome' => 'retry'], 503, 5);
            }

            if ($refused instanceof CredentialAuthorizationRefused && $authorizationId !== null) {
                $browser->forget($request, $authorizationId);
            }

            return $this->unavailable();
        }

        $redirect = new LoopbackRedirectUri((string) $result->redirectUri);
        $parameters = $result->status === CredentialAuthorizationStatus::Approved
            ? ['code' => $result->authorizationCode?->reveal() ?? '', 'state' => (string) $result->state]
            : ['error' => 'access_denied', 'state' => (string) $result->state];

        return redirect()->away($redirect->append($parameters), 303, $this->headers());
    }

    public function token(Request $request, ExchangeLoopbackAuthorization $exchange): JsonResponse
    {
        try {
            $input = ClosedRequestInput::json($request, ['code', 'redirect_uri', 'code_verifier']);

            foreach (['code', 'redirect_uri', 'code_verifier'] as $field) {
                if (! is_string($input[$field]) || $input[$field] === '' || strlen($input[$field]) > 2048) {
                    throw CredentialAuthorizationRefused::invalidRequest();
                }
            }

            $token = $exchange($request, $input['code'], $input['redirect_uri'], $input['code_verifier']);
        } catch (CredentialAuthorizationRefused $refused) {
            return $this->refusal($refused);
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

    /** @param array{payload: array<string, mixed>, authorization: object} $entry */
    private function consent(Request $request, array $entry): Response
    {
        $authorization = $entry['authorization'];
        $authorizationId = (string) $authorization->id;
        $redirect = new LoopbackRedirectUri((string) $authorization->redirect_uri);
        $host = parse_url($redirect->value, PHP_URL_HOST);
        $port = parse_url($redirect->value, PHP_URL_PORT);
        $sessionId = $request->session()->getId();
        $userId = $this->userId($request);

        return $this->view(['authorization' => [
            'appPurpose' => (string) $authorization->app_purpose,
            'audience' => (string) $authorization->audience,
            'installation' => (string) $authorization->installation_ref,
            'application' => (string) $authorization->application_ref,
            'ownership' => (string) $authorization->ownership,
            'label' => is_string($authorization->label) ? $authorization->label : null,
            'callbackAuthority' => (string) $host.':'.(string) $port,
            'approveNonce' => SubmissionNonce::issue($sessionId, $userId, CredentialVerb::Issue, $this->target($authorizationId, 'approve')),
            'denyNonce' => SubmissionNonce::issue($sessionId, $userId, CredentialVerb::Issue, $this->target($authorizationId, 'deny')),
        ], 'outcome' => null]);
    }

    private function target(string $authorizationId, string $action): string
    {
        return 'loopback-authorization:'.$authorizationId.':'.$action;
    }

    private function userId(Request $request): string
    {
        $user = $request->user();

        if (! $user instanceof Authenticatable || ! is_scalar($user->getAuthIdentifier())) {
            throw CredentialAuthorizationRefused::unavailable();
        }

        return (string) $user->getAuthIdentifier();
    }

    private function refusal(CredentialAuthorizationRefused $refused): JsonResponse
    {
        return $this->json(
            ['error' => $refused->error],
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
        return $this->view(['authorization' => null, 'outcome' => 'unavailable'], 404);
    }

    /** @param array<string, mixed> $data */
    private function view(array $data, int $status = 200, ?int $retryAfter = null): Response
    {
        $response = response()->view('bfc::authorizations.loopback', $data, $status, $this->headers());

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
