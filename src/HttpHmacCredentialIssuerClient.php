<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Contracts\HmacCredentialIssuerClient;
use ArtisanBuild\BuiltForCloud\Exceptions\HmacCredentialTransferRefused;
use Carbon\CarbonImmutable;
use Closure;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Str;
use Throwable;

/** Origin-pinned HTTP implementation of the trusted HMAC issuer channel. */
final class HttpHmacCredentialIssuerClient implements HmacCredentialIssuerClient
{
    public const string ACTIVATE_PATH = '/bfc/hmac-cutovers/activate';

    public const string STATUS_PATH = '/bfc/hmac-cutovers/status';

    private const int MAX_RESPONSE_BYTES = 24 * 1024;

    /** @var Closure(): array<string, string> */
    private readonly Closure $protectedAuthorization;

    /**
     * TLS credentials and trust roots are configured on the supplied HTTP
     * factory. The closure supplies fresh protected-route authorization.
     *
     * @param  Closure(): array<string, string>  $protectedAuthorization
     */
    public function __construct(
        private readonly Factory $http,
        private readonly string $issuerOrigin,
        Closure $protectedAuthorization,
    ) {
        $this->assertOrigin($issuerOrigin);
        $this->protectedAuthorization = $protectedAuthorization;
    }

    public function claim(BoundCredentialScope $expectedScope, SensitiveString $claimCode): ClaimedHmacCredential
    {
        try {
            $response = $this->request()->post($this->url('/bfc/onboarding/exchange'), [
                'token' => $claimCode->reveal(),
                'version' => 1,
            ]);
            $payload = $this->payload($response, 201, $this->claimFields());
            $scope = $this->scope($payload);

            if (! $this->sameScope($scope, $expectedScope)
                || ($payload['algorithm'] ?? null) !== CredentialAlgorithm::HmacSha256->value
                || ($payload['source_status'] ?? null) !== CredentialStatus::Pending->value
                || ! is_string($payload['signing_key'] ?? null)
                || ! is_int($payload['delivery_generation'] ?? null)
                || $payload['delivery_generation'] < 1
                || ! is_string($payload['delivery_fingerprint'] ?? null)
                || preg_match('/\A[0-9a-f]{16}\z/D', $payload['delivery_fingerprint']) !== 1
                || ! is_string($payload['credential_id'] ?? null)
                || ! Str::isUuid($payload['credential_id'])) {
                throw new HmacCredentialTransferRefused;
            }

            $deliveredAt = $this->date($payload['delivered_at'] ?? null);
            $transferExpiresAt = $this->date($payload['transfer_expires_at'] ?? null);
            $credentialExpiresAt = $this->nullableDate($payload, 'credential_expires_at');
            $predecessorId = $this->nullableUuid($payload, 'predecessor_credential_id');

            if ($deliveredAt->isFuture()
                || now()->greaterThan($transferExpiresAt)
                || $transferExpiresAt->greaterThan($deliveredAt->addSeconds(60))
                || ($credentialExpiresAt !== null && ! $credentialExpiresAt->isFuture())) {
                throw new HmacCredentialTransferRefused;
            }

            $transfer = HmacCredentialTransfer::fromIssuerResponse(
                $payload['credential_id'],
                $scope,
                CredentialAlgorithm::HmacSha256->value,
                $credentialExpiresAt,
                $payload['delivery_generation'],
                $payload['delivery_fingerprint'],
                $predecessorId,
                CredentialStatus::Pending,
                $deliveredAt,
                $transferExpiresAt,
            );

            return ClaimedHmacCredential::fromIssuerResponse(
                $transfer,
                ImportedHmacSecret::fromIssuerResponse($payload['signing_key']),
            );
        } catch (HmacCredentialTransferRefused $refused) {
            throw $refused;
        } catch (Throwable) {
            throw new HmacCredentialTransferRefused;
        }
    }

    public function activate(
        BoundCredentialScope $expectedScope,
        ?string $predecessorId,
        string $replacementId,
        string $deliveryFingerprint,
    ): IssuerHmacCutoverReceipt {
        try {
            return $this->receipt(
                $expectedScope,
                $predecessorId,
                $replacementId,
                $this->protectedRequest()->post($this->url(self::ACTIVATE_PATH), [
                    ...$this->scopePayload($expectedScope),
                    'predecessor_credential_id' => $predecessorId,
                    'replacement_credential_id' => $replacementId,
                    'delivery_fingerprint' => $deliveryFingerprint,
                ]),
            );
        } catch (HmacCredentialTransferRefused $refused) {
            throw $refused;
        } catch (Throwable) {
            throw new HmacCredentialTransferRefused;
        }
    }

    public function cutoverStatus(
        BoundCredentialScope $expectedScope,
        ?string $predecessorId,
        string $replacementId,
    ): IssuerHmacCutoverReceipt {
        try {
            return $this->receipt(
                $expectedScope,
                $predecessorId,
                $replacementId,
                $this->protectedRequest()->post($this->url(self::STATUS_PATH), [
                    ...$this->scopePayload($expectedScope),
                    'predecessor_credential_id' => $predecessorId,
                    'replacement_credential_id' => $replacementId,
                ]),
            );
        } catch (HmacCredentialTransferRefused $refused) {
            throw $refused;
        } catch (Throwable) {
            throw new HmacCredentialTransferRefused;
        }
    }

    private function receipt(
        BoundCredentialScope $expectedScope,
        ?string $expectedPredecessorId,
        string $expectedReplacementId,
        Response $response,
    ): IssuerHmacCutoverReceipt {
        try {
            $payload = $this->payload($response, 200, $this->receiptFields());
            $scope = $this->scope($payload);
            $predecessorId = $this->nullableUuid($payload, 'predecessor_credential_id');
            $replacementId = $payload['replacement_credential_id'] ?? null;
            $emergency = $payload['emergency'] ?? null;

            if (! $this->sameScope($scope, $expectedScope)
                || $predecessorId !== $expectedPredecessorId
                || ! is_string($replacementId)
                || ! Str::isUuid($replacementId)
                || ! hash_equals($expectedReplacementId, $replacementId)
                || ! is_bool($emergency)) {
                throw new HmacCredentialTransferRefused;
            }

            $activatedAt = $this->date($payload['activated_at'] ?? null);
            $predecessorExpiresAt = $this->nullableDate($payload, 'predecessor_expires_at');

            if (($predecessorId === null) !== ($predecessorExpiresAt === null)
                || $activatedAt->isFuture()) {
                throw new HmacCredentialTransferRefused;
            }

            return IssuerHmacCutoverReceipt::fromIssuerResponse(
                $predecessorId,
                $replacementId,
                $scope,
                $activatedAt,
                $predecessorExpiresAt,
                $emergency,
            );
        } catch (HmacCredentialTransferRefused $refused) {
            throw $refused;
        } catch (Throwable) {
            throw new HmacCredentialTransferRefused;
        }
    }

    private function request(): PendingRequest
    {
        return $this->http
            ->acceptJson()
            ->asJson()
            ->timeout(8)
            ->withOptions([
                'allow_redirects' => false,
                'on_headers' => static function ($response): void {
                    $length = $response->getHeaderLine('Content-Length');

                    if ($length !== '' && ctype_digit($length) && (int) $length > self::MAX_RESPONSE_BYTES) {
                        throw new HmacCredentialTransferRefused;
                    }
                },
                'progress' => static function (int $downloadTotal, int $downloaded): void {
                    if ($downloadTotal > self::MAX_RESPONSE_BYTES || $downloaded > self::MAX_RESPONSE_BYTES) {
                        throw new HmacCredentialTransferRefused;
                    }
                },
            ]);
    }

    private function protectedRequest(): PendingRequest
    {
        $headers = ($this->protectedAuthorization)();

        if ($headers === []) {
            throw new HmacCredentialTransferRefused;
        }

        foreach ($headers as $name => $value) {
            if (! is_string($name) || $name === '' || ! is_string($value) || $value === '') {
                throw new HmacCredentialTransferRefused;
            }
        }

        return $this->request()->withHeaders($headers);
    }

    /**
     * @param  list<string>  $expectedFields
     * @return array<string, mixed>
     */
    private function payload(Response $response, int $status, array $expectedFields): array
    {
        $body = $response->body();
        $contentType = strtolower($response->header('Content-Type'));
        $effectiveUrl = $response->handlerStats()['url'] ?? null;

        if ($response->status() !== $status
            || strlen($body) > self::MAX_RESPONSE_BYTES
            || ! str_starts_with($contentType, 'application/json')
            || (is_string($effectiveUrl) && ! $this->sameOrigin($effectiveUrl))) {
            throw new HmacCredentialTransferRefused;
        }

        try {
            $payload = json_decode($body, true, flags: JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            throw new HmacCredentialTransferRefused;
        }

        if (! is_array($payload) || array_is_list($payload)) {
            throw new HmacCredentialTransferRefused;
        }

        $actualFields = array_keys($payload);
        sort($actualFields);
        sort($expectedFields);

        if ($actualFields !== $expectedFields) {
            throw new HmacCredentialTransferRefused;
        }

        return $payload;
    }

    /** @param array<string, mixed> $payload */
    private function scope(array $payload): BoundCredentialScope
    {
        foreach (['app_purpose', 'subject_type', 'subject_ref', 'installation_ref', 'application_ref', 'audience'] as $field) {
            if (! is_string($payload[$field] ?? null)) {
                throw new HmacCredentialTransferRefused;
            }
        }

        $subjectType = SubjectType::tryFrom($payload['subject_type']);

        if ($subjectType === null) {
            throw new HmacCredentialTransferRefused;
        }

        return new BoundCredentialScope(
            $payload['app_purpose'],
            new Subject($subjectType, $payload['subject_ref']),
            $payload['installation_ref'],
            $payload['application_ref'],
            $payload['audience'],
        );
    }

    private function date(mixed $value): CarbonImmutable
    {
        if (! is_string($value)
            || preg_match('/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})\z/D', $value) !== 1) {
            throw new HmacCredentialTransferRefused;
        }

        try {
            $date = CarbonImmutable::parse($value);
        } catch (Throwable) {
            throw new HmacCredentialTransferRefused;
        }

        if ($date->format('Y-m-d\TH:i:sP') !== str_replace('Z', '+00:00', $value)) {
            throw new HmacCredentialTransferRefused;
        }

        return $date;
    }

    /** @param array<string, mixed> $payload */
    private function nullableDate(array $payload, string $field): ?CarbonImmutable
    {
        if (! array_key_exists($field, $payload)) {
            throw new HmacCredentialTransferRefused;
        }

        return $payload[$field] === null ? null : $this->date($payload[$field]);
    }

    /** @param array<string, mixed> $payload */
    private function nullableUuid(array $payload, string $field): ?string
    {
        if (! array_key_exists($field, $payload)) {
            throw new HmacCredentialTransferRefused;
        }

        $value = $payload[$field];

        if ($value !== null && (! is_string($value) || ! Str::isUuid($value))) {
            throw new HmacCredentialTransferRefused;
        }

        return $value;
    }

    /** @return array<string, string> */
    private function scopePayload(BoundCredentialScope $scope): array
    {
        return [
            'app_purpose' => $scope->appPurpose,
            'subject_type' => $scope->subject->type->value,
            'subject_ref' => $scope->subject->ref,
            'installation_ref' => $scope->installation,
            'application_ref' => $scope->application,
            'audience' => $scope->audience,
        ];
    }

    private function sameScope(BoundCredentialScope $left, BoundCredentialScope $right): bool
    {
        return $left->subject->type === $right->subject->type
            && hash_equals($left->subject->ref, $right->subject->ref)
            && hash_equals($left->appPurpose, $right->appPurpose)
            && hash_equals($left->installation, $right->installation)
            && hash_equals($left->application, $right->application)
            && hash_equals($left->audience, $right->audience);
    }

    private function url(string $path): string
    {
        return rtrim($this->issuerOrigin, '/').$path;
    }

    private function assertOrigin(string $origin): void
    {
        $parts = parse_url($origin);
        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        $host = strtolower((string) ($parts['host'] ?? ''));
        $loopback = in_array($host, ['localhost', '127.0.0.1', '::1'], true);

        if ($host === ''
            || isset($parts['user'])
            || isset($parts['pass'])
            || isset($parts['query'])
            || isset($parts['fragment'])
            || ! in_array($parts['path'] ?? '', ['', '/'], true)
            || ($scheme !== 'https' && ! ($scheme === 'http' && $loopback && app()->environment(['local', 'testing'])))) {
            throw new HmacCredentialTransferRefused;
        }
    }

    private function sameOrigin(string $url): bool
    {
        $expected = parse_url($this->issuerOrigin);
        $actual = parse_url($url);

        return strtolower((string) ($expected['scheme'] ?? '')) === strtolower((string) ($actual['scheme'] ?? ''))
            && strtolower((string) ($expected['host'] ?? '')) === strtolower((string) ($actual['host'] ?? ''))
            && $this->port($expected) === $this->port($actual);
    }

    /** @param array<string, mixed>|false $parts */
    private function port(array|false $parts): int
    {
        if (! is_array($parts)) {
            return 0;
        }

        return (int) ($parts['port'] ?? (strtolower((string) ($parts['scheme'] ?? '')) === 'https' ? 443 : 80));
    }

    /** @return list<string> */
    private function claimFields(): array
    {
        return [
            'signing_key', 'credential_id', 'app_purpose', 'subject_type', 'subject_ref',
            'installation_ref', 'application_ref', 'audience', 'algorithm', 'credential_expires_at',
            'delivery_generation', 'delivery_fingerprint', 'predecessor_credential_id', 'source_status',
            'delivered_at', 'transfer_expires_at',
        ];
    }

    /** @return list<string> */
    private function receiptFields(): array
    {
        return [
            'predecessor_credential_id', 'replacement_credential_id', 'app_purpose', 'subject_type',
            'subject_ref', 'installation_ref', 'application_ref', 'audience', 'activated_at',
            'predecessor_expires_at', 'emergency',
        ];
    }
}
