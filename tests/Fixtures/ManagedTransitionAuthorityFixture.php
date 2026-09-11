<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests\Fixtures;

use ArtisanBuild\BuiltForCloud\ManagedTransitionClient;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use RuntimeException;

final class ManagedTransitionAuthorityFixture
{
    /** @var list<array{leg: string, path: string, body: string, digest: ?string}> */
    public array $calls = [];

    /** @var array<string, int> */
    public array $executionCounts = [];

    /** @var array<string, list<array<string, mixed>>> */
    public array $rosterPages = [];

    /** @var null|callable(string, array<string, mixed>): array<string, mixed> */
    public mixed $transform = null;

    public ?string $crashAfterExecution = null;

    public bool $stageRosterChanged = false;

    /** @var array<string, array{digest: string, response: array<string, mixed>, status: int}> */
    private array $recorded = [];

    /** @var array<string, string> */
    private array $requestTransitions = [];

    /** @var array<string, array{status: string, receipt: ?string, direction: string}> */
    private array $transitions = [];

    public function __construct(
        private readonly string $baseUrl = 'https://transition-authority.example.test',
        private readonly string $clientSecret = 'transition-secret',
        private readonly string $issuer = 'https://issuer.example.test',
        private readonly string $connectionId = 'transition-connection',
        private readonly string $organizationId = 'transition-organization',
        private readonly string $installationId = 'transition-installation',
        private readonly int $generation = 7,
    ) {
        $this->rosterPages = [
            'NULL' => [[
                'scalpels_id' => 'direct-member',
                'membership_status' => 'active',
                'role' => 'member',
                'display_name' => 'Direct Member',
                'contact_email' => 'direct-member@example.test',
                'contact_email_verified' => true,
            ]],
        ];
    }

    public function respond(Request $request): mixed
    {
        $path = (string) parse_url($request->url(), PHP_URL_PATH);
        $body = $request->body();
        $data = json_decode($body, true);
        if (! is_array($data)) {
            throw new RuntimeException('Transition fixture received malformed JSON.');
        }

        if ($request->method() !== 'POST'
            || ($request->header('Bfc-Contract-Version')[0] ?? null) !== ManagedTransitionClient::CONTRACT_VERSION
            || ($request->header('Authorization')[0] ?? null) !== 'Bearer '.$this->clientSecret
            || ! str_starts_with((string) ($request->header('Content-Type')[0] ?? ''), 'application/json')
            || ! in_array($request->header('Content-Encoding')[0] ?? null, [null, 'identity'], true)) {
            return Http::response([
                'contract_version' => ManagedTransitionClient::CONTRACT_VERSION,
                'error' => 'invalid_client',
            ], 401);
        }

        $leg = $this->leg($path);
        $digest = $request->header('Bfc-Body-Digest')[0] ?? null;
        $this->calls[] = ['leg' => $leg, 'path' => $path, 'body' => $body, 'digest' => $digest];

        if (in_array($leg, ['T1', 'T3', 'T4', 'T7'], true)) {
            if (! is_string($digest) || ! hash_equals(hash('sha256', $body), $digest)) {
                return Http::response([
                    'contract_version' => ManagedTransitionClient::CONTRACT_VERSION,
                    'error' => 'idempotency_conflict',
                ], 409);
            }

            $key = $leg === 'T1' ? ($data['transition_request_id'] ?? null) : ($data['idempotency_key'] ?? null);
            if (! is_string($key) || $key === '') {
                throw new RuntimeException('Transition fixture received a keyed leg without its key.');
            }

            $scope = $leg === 'T1'
                ? implode(':', [$leg, $this->installationId, (string) $data['direction'], $key])
                : implode(':', [$leg, $this->transitionFromPath($path), $key]);
            if (isset($this->recorded[$scope])) {
                $recorded = $this->recorded[$scope];
                if (! hash_equals($recorded['digest'], $digest)) {
                    return Http::response([
                        'contract_version' => ManagedTransitionClient::CONTRACT_VERSION,
                        'error' => 'idempotency_conflict',
                    ], 409);
                }

                return Http::response($recorded['response'], $recorded['status']);
            }

            $this->assertRequest($leg, $data, $path);
            $response = $this->execute($leg, $data, $path);
            $response = $this->transform($leg, $response);
            $status = $leg === 'T3' && $this->stageRosterChanged ? 409 : 200;
            if ($status === 409) {
                $response = [
                    'contract_version' => ManagedTransitionClient::CONTRACT_VERSION,
                    'error' => 'roster_changed',
                ];
            }
            $this->recorded[$scope] = ['digest' => $digest, 'response' => $response, 'status' => $status];

            if ($this->crashAfterExecution === $leg) {
                $this->crashAfterExecution = null;
                throw new RuntimeException('Simulated outcome-unknown '.$leg.' crash.');
            }

            return Http::response($response, $status);
        }

        $this->assertRequest($leg, $data, $path);

        return Http::response($this->transform($leg, $this->execute($leg, $data, $path)));
    }

    /** @param array<string, mixed> $data @return array<string, mixed> */
    private function execute(string $leg, array $data, string $path): array
    {
        $this->executionCounts[$leg] = ($this->executionCounts[$leg] ?? 0) + 1;

        return match ($leg) {
            'T1' => $this->prepare($data),
            'T2' => $this->roster($data, $path),
            'T3' => $this->stage($data, $path),
            'T4' => $this->acknowledge($data, $path),
            'T5' => $this->state($path),
            'T6' => $this->recoverRequest($path),
            'T7' => $this->abandon($path),
            default => throw new RuntimeException('Unexpected transition fixture leg.'),
        };
    }

    /** @param array<string, mixed> $data @return array<string, mixed> */
    private function prepare(array $data): array
    {
        $requestId = $this->requiredString($data, 'transition_request_id');
        $transitionId = 'authority-transition-'.(count($this->requestTransitions) + 1);
        $this->requestTransitions[$requestId] = $transitionId;
        $direction = $this->requiredString($data, 'direction');
        $this->transitions[$transitionId] = ['status' => 'prepared', 'receipt' => null, 'direction' => $direction];

        return [
            ...$this->binding($this->generation),
            'transition_request_id' => $requestId,
            'transition_id' => $transitionId,
            'direction' => $direction,
            'status' => 'prepared',
            'roster_cutoff_at' => '2026-09-11T12:00:00+00:00',
            'roster_total' => count(array_merge(...array_values($this->rosterPages))),
        ];
    }

    /** @param array<string, mixed> $data @return array<string, mixed> */
    private function roster(array $data, string $path): array
    {
        $transitionId = $this->transitionFromPath($path);
        $cursor = $data['cursor'] ?? null;
        $key = $cursor === null ? 'NULL' : $this->requiredString($data, 'cursor');
        if (! array_key_exists($key, $this->rosterPages)) {
            throw new RuntimeException('Transition fixture received an unknown cursor.');
        }

        $keys = array_keys($this->rosterPages);
        $index = array_search($key, $keys, true);
        $next = is_int($index) && isset($keys[$index + 1]) ? $keys[$index + 1] : null;

        return [
            ...$this->binding($this->generation),
            'transition_id' => $transitionId,
            'roster_cutoff_at' => '2026-09-11T12:00:00+00:00',
            'members' => $this->rosterPages[$key],
            'next_cursor' => $next,
            'page_total' => count($this->rosterPages[$key]),
        ];
    }

    /** @param array<string, mixed> $data @return array<string, mixed> */
    private function stage(array $data, string $path): array
    {
        $transitionId = $this->transitionFromPath($path);
        if (! $this->stageRosterChanged) {
            $this->transitions[$transitionId]['status'] = 'staged';
        }

        return [
            ...$this->binding($this->generation),
            'transition_id' => $transitionId,
            'status' => 'staged',
            'roster_cutoff_at' => '2026-09-11T12:00:00+00:00',
        ];
    }

    /** @param array<string, mixed> $data @return array<string, mixed> */
    private function acknowledge(array $data, string $path): array
    {
        $transitionId = $this->transitionFromPath($path);
        $receipt = $this->requiredString($data, 'local_commit_receipt');
        $this->transitions[$transitionId]['status'] = 'acknowledged';
        $this->transitions[$transitionId]['receipt'] = $receipt;

        return [
            ...$this->binding($this->generation + 1),
            'transition_id' => $transitionId,
            'status' => 'acknowledged',
            'generation_after' => $this->generation + 1,
            'local_commit_receipt' => $receipt,
            'acknowledged_at' => '2026-09-11T12:05:00+00:00',
        ];
    }

    /** @return array<string, mixed> */
    private function state(string $path): array
    {
        $transitionId = $this->transitionFromPath($path);
        $state = $this->transitions[$transitionId];
        $acknowledged = $state['status'] === 'acknowledged';

        return [
            ...$this->binding($acknowledged ? $this->generation + 1 : $this->generation),
            'transition_id' => $transitionId,
            'direction' => $state['direction'],
            'status' => $state['status'],
            'roster_cutoff_at' => '2026-09-11T12:00:00+00:00',
            'local_commit_receipt' => $state['receipt'],
            'acknowledged_at' => $acknowledged ? '2026-09-11T12:05:00+00:00' : null,
        ];
    }

    /** @return array<string, mixed> */
    private function recoverRequest(string $path): array
    {
        $requestId = rawurldecode(substr($path, strrpos($path, '/') + 1));
        $transitionId = $this->requestTransitions[$requestId] ?? null;
        $status = $transitionId === null ? null : $this->transitions[$transitionId]['status'];

        return [
            ...$this->binding($status === 'acknowledged' ? $this->generation + 1 : $this->generation),
            'transition_request_id' => $requestId,
            'transition_id' => $transitionId,
            'status' => $status,
        ];
    }

    /** @return array<string, mixed> */
    private function abandon(string $path): array
    {
        $transitionId = $this->transitionFromPath($path);
        $this->transitions[$transitionId]['status'] = 'abandoned';
        $this->transitions[$transitionId]['receipt'] = null;

        return [
            ...$this->binding($this->generation),
            'transition_id' => $transitionId,
            'status' => 'abandoned',
        ];
    }

    /** @return array<string, int|string> */
    private function binding(int $generation): array
    {
        return [
            'contract_version' => ManagedTransitionClient::CONTRACT_VERSION,
            'issuer' => $this->issuer,
            'connection_id' => $this->connectionId,
            'organization_id' => $this->organizationId,
            'installation_id' => $this->installationId,
            'authority_generation' => $generation,
            'roster_version' => 41,
            'response_sequence' => 73,
            'responded_at' => '2026-09-11T12:00:01+00:00',
        ];
    }

    /** @param array<string, mixed> $payload @return array<string, mixed> */
    private function transform(string $leg, array $payload): array
    {
        return is_callable($this->transform) ? ($this->transform)($leg, $payload) : $payload;
    }

    private function leg(string $path): string
    {
        return match (true) {
            $path === '/managed-transition/v1/transitions' => 'T1',
            str_contains($path, '/transition-requests/') => 'T6',
            str_ends_with($path, '/roster') => 'T2',
            str_ends_with($path, '/stage') => 'T3',
            str_ends_with($path, '/ack') => 'T4',
            str_ends_with($path, '/abandon') => 'T7',
            preg_match('#^/managed-transition/v1/transitions/[^/]+$#', $path) === 1 => 'T5',
            default => throw new RuntimeException('Transition fixture received an unknown path.'),
        };
    }

    private function transitionFromPath(string $path): string
    {
        if (preg_match('#^/managed-transition/v1/transitions/([^/]+)#', $path, $matches) !== 1) {
            throw new RuntimeException('Transition fixture path has no transition ID.');
        }

        $transitionId = rawurldecode($matches[1]);
        if (! isset($this->transitions[$transitionId])) {
            throw new RuntimeException('Transition fixture received an unknown transition ID.');
        }

        return $transitionId;
    }

    /** @param array<string, mixed> $data */
    private function assertRequest(string $leg, array $data, string $path): void
    {
        $expectedKeys = match ($leg) {
            'T1' => ['connection_id', 'installation_id', 'direction', 'transition_request_id'],
            'T2' => ['connection_id', 'installation_id', 'roster_version', 'roster_cutoff_at', 'cursor'],
            'T3' => ['connection_id', 'installation_id', 'idempotency_key', 'roster_version', 'roster_cutoff_at', 'mapping'],
            'T4' => ['connection_id', 'installation_id', 'idempotency_key', 'local_commit_receipt', 'mode_after', 'generation_after'],
            'T5', 'T6' => ['connection_id', 'installation_id'],
            'T7' => ['connection_id', 'installation_id', 'idempotency_key'],
        };

        if (array_keys($data) !== $expectedKeys
            || ($data['connection_id'] ?? null) !== $this->connectionId
            || ($data['installation_id'] ?? null) !== $this->installationId) {
            throw new RuntimeException('Transition fixture received a request outside the frozen '.$leg.' shape.');
        }

        if (in_array($leg, ['T1', 'T3', 'T4', 'T7'], true)) {
            $field = $leg === 'T1' ? 'transition_request_id' : 'idempotency_key';
            if (! is_string($data[$field] ?? null)
                || preg_match('/^[A-Za-z0-9_-]{43}$/', $data[$field]) !== 1) {
                throw new RuntimeException('Transition fixture received a malformed '.$leg.' key.');
            }
        }

        if ($leg === 'T1' && ! in_array($data['direction'], ['adopt', 'exit'], true)) {
            throw new RuntimeException('Transition fixture received an invalid T1 direction.');
        }

        if ($leg === 'T2'
            && ($data['roster_version'] !== 41
                || $data['roster_cutoff_at'] !== '2026-09-11T12:00:00+00:00'
                || ($data['cursor'] !== null && ! is_string($data['cursor'])))) {
            throw new RuntimeException('Transition fixture received an invalid T2 snapshot binding.');
        }

        if ($leg === 'T3'
            && ($data['roster_version'] !== 41
                || $data['roster_cutoff_at'] !== '2026-09-11T12:00:00+00:00'
                || ! is_array($data['mapping']))) {
            throw new RuntimeException('Transition fixture received an invalid T3 snapshot binding.');
        }

        if ($leg === 'T4'
            && (($data['mode_after'] ?? null) !== ($this->transitions[$this->transitionFromPath($path)]['direction'] === 'adopt'
                ? 'managed'
                : 'standalone')
                || ($data['generation_after'] ?? null) !== 8
                || ! is_string($data['local_commit_receipt'] ?? null)
                || $data['local_commit_receipt'] === '')) {
            throw new RuntimeException('Transition fixture received an invalid T4 commit binding.');
        }
    }

    /** @param array<string, mixed> $payload */
    private function requiredString(array $payload, string $field): string
    {
        $value = $payload[$field] ?? null;
        if (! is_string($value) || $value === '') {
            throw new RuntimeException('Transition fixture received a malformed '.$field.'.');
        }

        return $value;
    }
}
