<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\ManagedAuthClient;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use RuntimeException;

final class ManagedAuthorityFixture
{
    /** @var list<array{method: string, path: string, body: array<string, mixed>}> */
    public array $calls = [];

    /** @var array<string, mixed> */
    public array $exchangeOverrides = [];

    /** @var array<string, mixed> */
    public array $confirmationOverrides = [];

    /** @var array<string, mixed> */
    public array $ownershipOverrides = [];

    /** @var null|callable(array<string, mixed>): array<string, mixed> */
    public mixed $handoffTransform = null;

    /** @var null|callable(array<string, mixed>): array<string, mixed> */
    public mixed $exchangeTransform = null;

    /** @var null|callable(array<string, mixed>, array<string, mixed>): mixed */
    public mixed $confirmationResponder = null;

    /** @var null|callable(array<string, mixed>, array<string, mixed>): mixed */
    public mixed $ownershipResponder = null;

    public function __construct(
        private readonly string $baseUrl,
        private readonly string $clientSecret,
        private readonly string $issuer,
        private readonly string $connectionId,
        private readonly string $organizationId,
        private readonly string $installationId,
        private readonly int $authorityGeneration,
    ) {}

    public function respond(Request $request): mixed
    {
        $path = (string) parse_url($request->url(), PHP_URL_PATH);
        $body = $request->data();
        $this->calls[] = ['method' => $request->method(), 'path' => $path, 'body' => $body];
        $contractVersion = $path === '/managed-transition/v1/ownership'
            ? ManagedAuthClient::TRANSITION_CONTRACT_VERSION
            : ManagedAuthClient::CONTRACT_VERSION;

        if ($request->method() !== 'POST'
            || ($request->header('Bfc-Contract-Version')[0] ?? null) !== $contractVersion
            || ($request->header('Authorization')[0] ?? null) !== 'Bearer '.$this->clientSecret) {
            return Http::response([
                'contract_version' => $contractVersion,
                'error' => 'invalid_client',
            ], 401);
        }

        if ($path === '/managed-auth/v1/handoffs') {
            $this->assertExactBody($body, [
                'connection_id' => $this->connectionId,
                'installation_id' => $this->installationId,
                'request_id' => null,
            ]);

            $payload = [
                'contract_version' => ManagedAuthClient::CONTRACT_VERSION,
                'request_id' => $body['request_id'],
                'authorization_url' => $this->baseUrl.ManagedAuthClient::AUTHORIZE_PATH,
                'expires_at' => now()->addSeconds(90)->toAtomString(),
            ];

            if (is_callable($this->handoffTransform)) {
                $payload = ($this->handoffTransform)($payload);
            }

            return Http::response($payload);
        }

        if (preg_match('#^/managed-auth/v1/handoffs/([^/]+)/exchange$#', $path, $match) === 1) {
            $requestId = rawurldecode($match[1]);
            $this->assertExactBody($body, [
                'connection_id' => $this->connectionId,
                'installation_id' => $this->installationId,
                'code' => null,
            ]);

            $payload = array_merge($this->binding(), [
                'scalpels_id' => 'subject-fixture',
                'membership_id' => 'membership-fixture',
                'membership_status' => 'active',
                'connection_status' => 'active',
                'role' => 'member',
                'display_name' => 'Fixture Member',
                'contact_email' => 'fixture-member@example.test',
                'contact_email_verified' => true,
                '_request_id_observed' => $requestId,
            ], $this->exchangeOverrides);

            if (is_callable($this->exchangeTransform)) {
                $payload = ($this->exchangeTransform)($payload);
            }

            return Http::response($payload);
        }

        if ($path === '/managed-auth/v1/memberships/confirm') {
            $this->assertConfirmationBody($body);
            $payload = array_merge($this->binding(), [
                'scalpels_id' => $body['scalpels_id'],
                'membership_status' => 'active',
                'connection_status' => 'active',
                'role' => 'member',
                'roster_version' => ((int) $body['roster_version']) + 1,
                'response_sequence' => ((int) $body['response_sequence']) + 1,
                'responded_at' => now()->toAtomString(),
            ], $this->confirmationOverrides);

            if (is_callable($this->confirmationResponder)) {
                return ($this->confirmationResponder)($body, $payload);
            }

            return Http::response($payload);
        }

        if ($path === '/managed-transition/v1/ownership') {
            if (array_keys($body) !== [
                'connection_id',
                'installation_id',
                'seated_owner_scalpels_id',
            ]
                || $body['connection_id'] !== $this->connectionId
                || $body['installation_id'] !== $this->installationId
                || ($body['seated_owner_scalpels_id'] !== null
                    && (! is_string($body['seated_owner_scalpels_id'])
                        || $body['seated_owner_scalpels_id'] === ''))) {
                throw new RuntimeException('Fixture received a request outside managed-transition-v1 O1.');
            }

            $payload = array_merge($this->binding(), [
                'contract_version' => ManagedAuthClient::TRANSITION_CONTRACT_VERSION,
                'owner' => [
                    'scalpels_id' => 'subject-fixture',
                    'membership_status' => 'active',
                    'role' => 'owner',
                ],
                'seated_owner' => is_string($body['seated_owner_scalpels_id'])
                    ? [
                        'scalpels_id' => $body['seated_owner_scalpels_id'],
                        'membership_status' => 'active',
                        'role' => 'admin',
                    ]
                    : null,
                'roster_version' => 9,
                'response_sequence' => 14,
            ], $this->ownershipOverrides);

            if (is_callable($this->ownershipResponder)) {
                return ($this->ownershipResponder)($body, $payload);
            }

            return Http::response($payload);
        }

        return Http::response([
            'contract_version' => ManagedAuthClient::CONTRACT_VERSION,
            'error' => 'server_error',
        ], 500);
    }

    /** @return array<string, int|string> */
    public function binding(): array
    {
        return [
            'contract_version' => ManagedAuthClient::CONTRACT_VERSION,
            'issuer' => $this->issuer,
            'connection_id' => $this->connectionId,
            'organization_id' => $this->organizationId,
            'installation_id' => $this->installationId,
            'authority_generation' => $this->authorityGeneration,
            'roster_version' => 8,
            'response_sequence' => 13,
            'responded_at' => now()->toAtomString(),
        ];
    }

    /**
     * @param  array<string, mixed>  $actual
     * @param  array<string, mixed>  $expected
     */
    private function assertExactBody(array $actual, array $expected): void
    {
        if (array_keys($actual) !== array_keys($expected)) {
            throw new RuntimeException('Fixture received a request outside managed-auth-v1.');
        }

        foreach ($expected as $field => $value) {
            if ($value !== null && $actual[$field] !== $value) {
                throw new RuntimeException('Fixture received a wrongly bound managed-auth-v1 request.');
            }

            if ($value === null && (! is_string($actual[$field]) || $actual[$field] === '')) {
                throw new RuntimeException('Fixture received a malformed managed-auth-v1 request.');
            }
        }
    }

    /** @param array<string, mixed> $body */
    private function assertConfirmationBody(array $body): void
    {
        if (array_keys($body) !== [
            'contract_version',
            'issuer',
            'connection_id',
            'organization_id',
            'installation_id',
            'authority_generation',
            'roster_version',
            'response_sequence',
            'responded_at',
            'scalpels_id',
        ]
            || $body['contract_version'] !== ManagedAuthClient::CONTRACT_VERSION
            || $body['issuer'] !== $this->issuer
            || $body['connection_id'] !== $this->connectionId
            || $body['organization_id'] !== $this->organizationId
            || $body['installation_id'] !== $this->installationId
            || $body['authority_generation'] !== $this->authorityGeneration
            || ! is_int($body['roster_version'])
            || ! is_int($body['response_sequence'])
            || ! is_string($body['responded_at'])
            || ! is_string($body['scalpels_id'])
            || $body['scalpels_id'] === '') {
            throw new RuntimeException('Fixture received a confirmation outside managed-auth-v1.');
        }
    }
}
