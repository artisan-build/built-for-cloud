<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Exceptions\ManagedAuthRefused;
use DateTimeImmutable;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Response;
use Throwable;

final class ManagedAuthClient
{
    public const string CONTRACT_VERSION = 'managed-auth-v1';

    public const string TRANSITION_CONTRACT_VERSION = 'managed-transition-v1';

    public const string AUTHORIZE_PATH = '/managed-auth/v1/authorize';

    private const string CONTRACT_HEADER = 'Bfc-Contract-Version';

    public function __construct(private readonly Factory $http) {}

    public function createHandoff(ManagedAuthConnection $connection, string $requestId): ManagedHandoffAuthorization
    {
        $response = $this->post(
            $this->request($connection),
            $connection->baseUrl.'/managed-auth/v1/handoffs',
            [
                'connection_id' => $connection->connectionId,
                'installation_id' => $connection->installationId,
                'request_id' => $requestId,
            ],
        );
        $payload = $this->successfulPayload($response, self::CONTRACT_VERSION);

        if (($payload['request_id'] ?? null) !== $requestId
            || ! is_string($payload['authorization_url'] ?? null)
            || ! $connection->acceptsAuthorizationUrl($payload['authorization_url'])
            || ! is_string($payload['expires_at'] ?? null)) {
            throw new ManagedAuthRefused;
        }

        return new ManagedHandoffAuthorization(
            $payload['authorization_url'],
            $this->date($payload['expires_at']),
        );
    }

    public function exchange(
        ManagedAuthConnection $connection,
        string $requestId,
        string $code,
    ): ManagedAuthExchange {
        $response = $this->post(
            $this->request($connection),
            $connection->baseUrl.'/managed-auth/v1/handoffs/'.rawurlencode($requestId).'/exchange',
            [
                'connection_id' => $connection->connectionId,
                'installation_id' => $connection->installationId,
                'code' => $code,
            ],
        );
        $payload = $this->successfulPayload($response, self::CONTRACT_VERSION);

        foreach ([
            'issuer' => $connection->issuer,
            'connection_id' => $connection->connectionId,
            'organization_id' => $connection->organizationId,
            'installation_id' => $connection->installationId,
            'authority_generation' => $connection->authorityGeneration,
        ] as $field => $expected) {
            if (($payload[$field] ?? null) !== $expected) {
                throw new ManagedAuthRefused;
            }
        }

        $scalpelsId = $this->requiredString($payload, 'scalpels_id');
        $membershipId = $this->requiredString($payload, 'membership_id');
        $membershipStatus = $this->requiredEnum($payload, 'membership_status', ['active', 'removed', 'disabled']);
        $connectionStatus = $this->requiredEnum($payload, 'connection_status', ['active', 'inactive']);
        $role = $this->requiredEnum($payload, 'role', ['owner', 'admin', 'member']);
        $displayName = $payload['display_name'] ?? null;
        $contactEmail = $this->requiredString($payload, 'contact_email');
        $contactEmailVerified = $payload['contact_email_verified'] ?? null;
        $rosterVersion = $this->unsignedInteger($payload, 'roster_version');
        $responseSequence = $this->unsignedInteger($payload, 'response_sequence');

        if (! is_string($displayName)
            || ! is_bool($contactEmailVerified)) {
            throw new ManagedAuthRefused;
        }

        return new ManagedAuthExchange(
            $scalpelsId,
            $membershipId,
            $membershipStatus,
            $connectionStatus,
            $role,
            $displayName,
            $contactEmail,
            $contactEmailVerified,
            $rosterVersion,
            $responseSequence,
            $this->date($this->requiredString($payload, 'responded_at')),
        );
    }

    public function confirm(ManagedAuthConnection $connection, User $user): ManagedAuthConfirmation
    {
        $response = $this->post(
            $this->request($connection),
            $connection->baseUrl.'/managed-auth/v1/memberships/confirm',
            [
                'contract_version' => self::CONTRACT_VERSION,
                'issuer' => $connection->issuer,
                'connection_id' => $connection->connectionId,
                'organization_id' => $connection->organizationId,
                'installation_id' => $connection->installationId,
                'authority_generation' => $connection->authorityGeneration,
                'roster_version' => $user->managed_membership_roster_version ?? 0,
                'response_sequence' => $user->managed_membership_response_sequence ?? 0,
                'responded_at' => $user->managed_membership_responded_at ?? '1970-01-01T00:00:00+00:00',
                'scalpels_id' => $user->scalpels_id,
            ],
        );
        $payload = $this->successfulPayload($response, self::CONTRACT_VERSION);

        foreach ([
            'issuer' => $connection->issuer,
            'connection_id' => $connection->connectionId,
            'organization_id' => $connection->organizationId,
            'installation_id' => $connection->installationId,
            'authority_generation' => $connection->authorityGeneration,
            'scalpels_id' => $user->scalpels_id,
        ] as $field => $expected) {
            if (($payload[$field] ?? null) !== $expected) {
                throw new ManagedAuthRefused;
            }
        }

        try {
            return new ManagedAuthConfirmation(
                $this->requiredString($payload, 'scalpels_id'),
                $this->requiredEnum($payload, 'membership_status', ['active', 'removed', 'disabled']),
                $this->requiredEnum($payload, 'connection_status', ['active', 'inactive']),
                $this->requiredEnum($payload, 'role', ['owner', 'admin', 'member']),
                $this->unsignedInteger($payload, 'roster_version'),
                $this->unsignedInteger($payload, 'response_sequence'),
                $this->date($this->requiredString($payload, 'responded_at')),
            );
        } catch (ManagedAuthRefused $exception) {
            throw new ManagedAuthRefused(previous: $exception, recordsFailedAttempt: true);
        }
    }

    public function ownership(
        ManagedAuthConnection $connection,
        ?string $seatedOwnerScalpelsId,
    ): ManagedOwnershipStatement {
        $response = $this->post(
            $this->request($connection, self::TRANSITION_CONTRACT_VERSION),
            $connection->baseUrl.'/managed-transition/v1/ownership',
            [
                'connection_id' => $connection->connectionId,
                'installation_id' => $connection->installationId,
                'seated_owner_scalpels_id' => $seatedOwnerScalpelsId,
            ],
        );
        $payload = $this->successfulPayload($response, self::TRANSITION_CONTRACT_VERSION);

        foreach ([
            'issuer' => $connection->issuer,
            'connection_id' => $connection->connectionId,
            'organization_id' => $connection->organizationId,
            'installation_id' => $connection->installationId,
            'authority_generation' => $connection->authorityGeneration,
        ] as $field => $expected) {
            if (($payload[$field] ?? null) !== $expected) {
                throw new ManagedAuthRefused;
            }
        }

        if (! array_key_exists('owner', $payload)
            || ! array_key_exists('seated_owner', $payload)
            || ! is_array($payload['owner'])
            || ($payload['seated_owner'] !== null && ! is_array($payload['seated_owner']))) {
            throw new ManagedAuthRefused;
        }

        return new ManagedOwnershipStatement(
            $seatedOwnerScalpelsId,
            $this->ownershipSubject($payload['owner']),
            is_array($payload['seated_owner'])
                ? $this->ownershipSubject($payload['seated_owner'])
                : null,
            $this->unsignedInteger($payload, 'roster_version'),
            $this->unsignedInteger($payload, 'response_sequence'),
            $this->date($this->requiredString($payload, 'responded_at')),
        );
    }

    private function request(
        ManagedAuthConnection $connection,
        string $contractVersion = self::CONTRACT_VERSION,
    ): PendingRequest
    {
        $request = $this->http
            ->acceptJson()
            ->asJson()
            ->withToken($connection->clientSecret)
            ->withHeaders([self::CONTRACT_HEADER => $contractVersion])
            ->timeout(8);

        return $connection->caBundle === null
            ? $request
            : $request->withOptions(['verify' => $connection->caBundle]);
    }

    /** @param array<string, mixed> $payload */
    private function post(PendingRequest $request, string $url, array $payload): Response
    {
        try {
            return $request->post($url, $payload);
        } catch (Throwable $exception) {
            throw new ManagedAuthRefused(
                $exception->getMessage(),
                previous: $exception,
                recordsFailedAttempt: true,
            );
        }
    }

    /** @return array<string, mixed> */
    private function successfulPayload(Response $response, string $contractVersion): array
    {
        $payload = $response->json();
        $retryAfter = $this->retryAfter($response);

        if (! is_array($payload) || ($payload['contract_version'] ?? null) !== $contractVersion) {
            throw new ManagedAuthRefused(
                retryAfterSeconds: $retryAfter,
                recordsFailedAttempt: true,
            );
        }

        if ($response->status() !== 200) {
            throw new ManagedAuthRefused(
                retryAfterSeconds: $retryAfter,
                recordsFailedAttempt: true,
            );
        }

        return $payload;
    }

    /** @param array<string, mixed> $payload */
    private function ownershipSubject(array $payload): ManagedOwnershipSubject
    {
        $scalpelsId = $this->requiredString($payload, 'scalpels_id');

        if (strlen($scalpelsId) > 255) {
            throw new ManagedAuthRefused;
        }

        return new ManagedOwnershipSubject(
            $scalpelsId,
            $this->requiredEnum($payload, 'membership_status', ['active', 'removed', 'disabled']),
            $this->requiredEnum($payload, 'role', ['owner', 'admin', 'member']),
        );
    }

    /** @param array<string, mixed> $payload */
    private function requiredString(array $payload, string $field): string
    {
        $value = $payload[$field] ?? null;

        if (! is_string($value) || $value === '') {
            throw new ManagedAuthRefused;
        }

        return $value;
    }

    /**
     * @param  array<string, mixed>  $payload
     * @param  list<string>  $allowed
     */
    private function requiredEnum(array $payload, string $field, array $allowed): string
    {
        $value = $this->requiredString($payload, $field);

        if (! in_array($value, $allowed, true)) {
            throw new ManagedAuthRefused;
        }

        return $value;
    }

    /** @param array<string, mixed> $payload */
    private function unsignedInteger(array $payload, string $field): int
    {
        $value = $payload[$field] ?? null;

        if (! is_int($value) || $value < 0) {
            throw new ManagedAuthRefused;
        }

        return $value;
    }

    private function date(string $value): DateTimeImmutable
    {
        if (preg_match(
            '/\A(\d{4})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])[Tt](?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d+)?(?:[Zz]|[+-](?:[01]\d|2[0-3]):[0-5]\d)\z/D',
            $value,
            $parts,
        ) !== 1 || ! checkdate((int) $parts[2], (int) $parts[3], (int) $parts[1])) {
            throw new ManagedAuthRefused;
        }

        try {
            return new DateTimeImmutable($value);
        } catch (Throwable) {
            throw new ManagedAuthRefused;
        }
    }

    private function retryAfter(Response $response): ?int
    {
        $value = trim($response->header('Retry-After'));

        if ($value === '' || ! ctype_digit($value)) {
            return null;
        }

        return min((int) $value, 300);
    }
}
