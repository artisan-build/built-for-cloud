<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Exceptions\ManagedAuthRefused;
use DateTimeImmutable;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Response;
use Throwable;

/** @internal The stateful ManagedTransitions service is the public capability boundary. */
final class ManagedTransitionClient
{
    public const string CONTRACT_VERSION = 'managed-transition-v1';

    private const string CONTRACT_HEADER = 'Bfc-Contract-Version';

    private const string DIGEST_HEADER = 'Bfc-Body-Digest';

    private const int MAX_SAFE_INTEGER = 9_007_199_254_740_991;

    private const int MAX_ROSTER_RESPONSE_BYTES = 1_048_576;

    public function __construct(private readonly Factory $http) {}

    public function prepare(ManagedTransition $transition): ManagedTransitionAuthorityState
    {
        $transition = $this->record($transition, [ManagedTransitionStatus::Preparing]);
        $payload = $this->payload($this->keyedPost(
            $transition,
            '/managed-transition/v1/transitions',
            $transition->prepare_request_body,
            $transition->prepare_body_digest,
        ));
        $this->binding($payload, $transition, $transition->generation_before);

        $state = new ManagedTransitionAuthorityState(
            $this->requiredString($payload, 'transition_request_id', 255),
            $this->requiredString($payload, 'transition_id', 255),
            ManagedTransitionDirection::from($this->requiredEnum($payload, 'direction', ['adopt', 'exit'])),
            $this->requiredEnum($payload, 'status', ['prepared']),
            $this->unsignedInteger($payload, 'roster_version'),
            $this->dateString($payload, 'roster_cutoff_at'),
            $this->unsignedInteger($payload, 'roster_total'),
            $transition->generation_before,
            null,
            null,
        );

        if ($state->transitionRequestId !== $transition->transition_request_id
            || $state->direction !== $transition->direction
            || $state->rosterTotal > 50_000) {
            throw new ManagedAuthRefused;
        }

        return $state;
    }

    public function roster(ManagedTransition $transition, ?string $cursor): ManagedTransitionRosterPage
    {
        $transition = $this->record($transition, [ManagedTransitionStatus::Prepared]);
        $this->requiredTransitionSnapshot($transition);
        $body = $this->serialize([
            'connection_id' => $transition->connection_id,
            'installation_id' => $transition->installation_id,
            'roster_version' => $transition->roster_version,
            'roster_cutoff_at' => $transition->roster_cutoff_at,
            'cursor' => $cursor,
        ]);
        $response = $this->post(
            $this->request($transition)
                ->withOptions([
                    'decode_content' => false,
                    'progress' => static function (int $total, int $received): void {
                        if ($total > self::MAX_ROSTER_RESPONSE_BYTES || $received > self::MAX_ROSTER_RESPONSE_BYTES) {
                            throw new ManagedAuthRefused;
                        }
                    },
                ])
                ->withBody($body, 'application/json'),
            $transition->authority_base_url.'/managed-transition/v1/transitions/'
                .rawurlencode((string) $transition->transition_id).'/roster',
        );

        $contentEncoding = strtolower(trim($response->header('Content-Encoding')));
        if (! in_array($contentEncoding, ['', 'identity'], true)
            || strlen($response->body()) > self::MAX_ROSTER_RESPONSE_BYTES) {
            throw new ManagedAuthRefused;
        }

        $payload = $this->payload($response);
        $this->binding($payload, $transition, $transition->generation_before);

        if (($payload['transition_id'] ?? null) !== $transition->transition_id
            || $this->unsignedInteger($payload, 'roster_version') !== $transition->roster_version
            || $this->dateString($payload, 'roster_cutoff_at') !== $transition->roster_cutoff_at
            || ! array_key_exists('members', $payload)
            || ! is_array($payload['members'])
            || ! array_is_list($payload['members'])
            || count($payload['members']) > 500) {
            throw new ManagedAuthRefused;
        }

        $members = [];
        foreach ($payload['members'] as $member) {
            if (! is_array($member)) {
                throw new ManagedAuthRefused;
            }

            $members[] = $this->member($member);
        }

        $pageTotal = $this->unsignedInteger($payload, 'page_total');
        if ($pageTotal > 500 || $pageTotal !== count($members)) {
            throw new ManagedAuthRefused;
        }

        return new ManagedTransitionRosterPage(
            $members,
            $this->nullableString($payload, 'next_cursor', 4096, true),
            $pageTotal,
        );
    }

    public function stage(ManagedTransition $transition): ManagedTransitionAuthorityState
    {
        $transition = $this->record($transition, [ManagedTransitionStatus::Staging]);
        $this->requiredTransitionSnapshot($transition);
        $body = $this->requiredRecordedRequest($transition->stage_request_body, $transition->stage_body_digest);
        $payload = $this->payload($this->keyedPost(
            $transition,
            '/managed-transition/v1/transitions/'.rawurlencode((string) $transition->transition_id).'/stage',
            $body,
            (string) $transition->stage_body_digest,
        ));
        $this->binding($payload, $transition, $transition->generation_before);

        return $this->boundSnapshotState($payload, $transition, 'staged');
    }

    public function acknowledge(ManagedTransition $transition): ManagedTransitionAuthorityState
    {
        $transition = $this->record($transition, [ManagedTransitionStatus::Acknowledging]);
        $this->requiredTransitionSnapshot($transition);
        $body = $this->requiredRecordedRequest($transition->ack_request_body, $transition->ack_body_digest);
        $payload = $this->payload($this->keyedPost(
            $transition,
            '/managed-transition/v1/transitions/'.rawurlencode((string) $transition->transition_id).'/ack',
            $body,
            (string) $transition->ack_body_digest,
        ));
        $this->binding($payload, $transition, $transition->generation_after);

        $rosterVersion = $this->unsignedInteger($payload, 'roster_version');
        $receipt = $this->requiredString($payload, 'local_commit_receipt', 255);
        $acknowledgedAt = $this->dateString($payload, 'acknowledged_at');

        if (($payload['transition_id'] ?? null) !== $transition->transition_id
            || $this->requiredEnum($payload, 'status', ['acknowledged']) !== 'acknowledged'
            || $rosterVersion !== $transition->roster_version
            || $this->unsignedInteger($payload, 'generation_after') !== $transition->generation_after
            || $receipt !== $transition->local_commit_receipt) {
            throw new ManagedAuthRefused;
        }

        return new ManagedTransitionAuthorityState(
            null,
            $transition->transition_id,
            null,
            'acknowledged',
            $rosterVersion,
            null,
            null,
            $transition->generation_after,
            $receipt,
            $acknowledgedAt,
        );
    }

    public function state(ManagedTransition $transition): ManagedTransitionAuthorityState
    {
        $transition = $this->record($transition, [
            ManagedTransitionStatus::Prepared,
            ManagedTransitionStatus::Rostered,
            ManagedTransitionStatus::Proposed,
            ManagedTransitionStatus::Staging,
            ManagedTransitionStatus::Staged,
            ManagedTransitionStatus::Committed,
            ManagedTransitionStatus::Acknowledging,
        ]);
        $this->requiredTransitionSnapshot($transition);
        $body = $this->serialize([
            'connection_id' => $transition->connection_id,
            'installation_id' => $transition->installation_id,
        ]);
        $payload = $this->payload($this->post(
            $this->request($transition)->withBody($body, 'application/json'),
            $transition->authority_base_url.'/managed-transition/v1/transitions/'
                .rawurlencode((string) $transition->transition_id),
        ));
        $status = $this->requiredEnum($payload, 'status', ['prepared', 'staged', 'acknowledged', 'abandoned']);
        $generation = $status === 'acknowledged'
            ? $transition->generation_after
            : $transition->generation_before;
        $this->binding($payload, $transition, $generation);
        if ($this->requiredEnum($payload, 'direction', ['adopt', 'exit']) !== $transition->direction->value) {
            throw new ManagedAuthRefused;
        }
        $state = $this->boundSnapshotState($payload, $transition, $status);
        $receipt = $this->nullableString($payload, 'local_commit_receipt', 255);
        $acknowledgedAt = $this->nullableDateString($payload, 'acknowledged_at');

        if (($status === 'acknowledged'
                && ($receipt !== $transition->local_commit_receipt || $acknowledgedAt === null))
            || ($status !== 'acknowledged' && ($receipt !== null || $acknowledgedAt !== null))) {
            throw new ManagedAuthRefused;
        }

        return new ManagedTransitionAuthorityState(
            null,
            $state->transitionId,
            $transition->direction,
            $status,
            $state->rosterVersion,
            $state->rosterCutoffAt,
            null,
            $generation,
            $receipt,
            $acknowledgedAt,
        );
    }

    public function recoverRequest(ManagedTransition $transition): ManagedTransitionAuthorityState
    {
        $transition = $this->record($transition, [ManagedTransitionStatus::Preparing]);
        $body = $this->serialize([
            'connection_id' => $transition->connection_id,
            'installation_id' => $transition->installation_id,
        ]);
        $payload = $this->payload($this->post(
            $this->request($transition)->withBody($body, 'application/json'),
            $transition->authority_base_url.'/managed-transition/v1/transition-requests/'
                .rawurlencode($transition->transition_request_id),
        ));
        $requestId = $this->requiredString($payload, 'transition_request_id', 255);
        $status = $this->nullableEnum($payload, 'status', ['prepared', 'staged', 'acknowledged', 'abandoned']);
        $transitionId = $this->nullableString($payload, 'transition_id', 255);

        if ($requestId !== $transition->transition_request_id
            || (($status === null) !== ($transitionId === null))) {
            throw new ManagedAuthRefused;
        }

        $generation = $status === 'acknowledged'
            ? $transition->generation_after
            : $transition->generation_before;
        $this->binding($payload, $transition, $generation);

        return new ManagedTransitionAuthorityState(
            $requestId,
            $transitionId,
            null,
            $status,
            $this->unsignedInteger($payload, 'roster_version'),
            null,
            null,
            $generation,
            null,
            null,
        );
    }

    public function abandon(ManagedTransition $transition): ManagedTransitionAuthorityState
    {
        $transition = $this->record($transition, [
            ManagedTransitionStatus::Prepared,
            ManagedTransitionStatus::Rostered,
            ManagedTransitionStatus::Proposed,
            ManagedTransitionStatus::Staged,
        ]);
        $this->requiredTransitionSnapshot($transition);
        $body = $this->requiredRecordedRequest($transition->abandon_request_body, $transition->abandon_body_digest);
        $payload = $this->payload($this->keyedPost(
            $transition,
            '/managed-transition/v1/transitions/'.rawurlencode((string) $transition->transition_id).'/abandon',
            $body,
            (string) $transition->abandon_body_digest,
        ));
        $this->binding($payload, $transition, $transition->generation_before);

        $rosterVersion = $this->unsignedInteger($payload, 'roster_version');
        if (($payload['transition_id'] ?? null) !== $transition->transition_id
            || $this->requiredEnum($payload, 'status', ['abandoned']) !== 'abandoned'
            || $rosterVersion !== $transition->roster_version) {
            throw new ManagedAuthRefused;
        }

        return new ManagedTransitionAuthorityState(
            null,
            $transition->transition_id,
            null,
            'abandoned',
            $rosterVersion,
            null,
            null,
            $transition->generation_before,
            null,
            null,
        );
    }

    /** @param list<ManagedTransitionStatus> $allowed */
    private function record(ManagedTransition $supplied, array $allowed): ManagedTransition
    {
        if (! $supplied->exists) {
            throw new ManagedAuthRefused;
        }

        $persisted = ManagedTransition::query()->find($supplied->getKey());
        if (! $persisted instanceof ManagedTransition
            || $persisted->status !== $supplied->status
            || ! in_array($persisted->status, $allowed, true)) {
            throw new ManagedAuthRefused;
        }

        foreach ([
            'issuer', 'connection_id', 'organization_id', 'installation_id', 'authority_base_url',
            'authority_ca_bundle', 'client_credential_reference', 'mode_before', 'mode_after',
            'generation_before', 'generation_after', 'transition_request_id', 'transition_id',
            'roster_version', 'roster_cutoff_at', 'local_commit_receipt',
        ] as $field) {
            if ($persisted->getAttribute($field) !== $supplied->getAttribute($field)) {
                throw new ManagedAuthRefused;
            }
        }

        return $persisted;
    }

    private function request(ManagedTransition $transition): PendingRequest
    {
        $secret = config($transition->client_credential_reference);
        if (! is_string($secret) || $secret === '') {
            throw new ManagedAuthRefused;
        }

        $request = $this->http
            ->acceptJson()
            ->withToken($secret)
            ->withHeaders([self::CONTRACT_HEADER => self::CONTRACT_VERSION])
            ->timeout(8);

        return $transition->authority_ca_bundle === null
            ? $request
            : $request->withOptions(['verify' => $transition->authority_ca_bundle]);
    }

    private function keyedPost(
        ManagedTransition $transition,
        string $path,
        string $body,
        string $digest,
    ): Response {
        if (! hash_equals(hash('sha256', $body), $digest)) {
            throw new ManagedAuthRefused;
        }

        return $this->post(
            $this->request($transition)
                ->withHeaders([self::DIGEST_HEADER => $digest])
                ->withBody($body, 'application/json'),
            $transition->authority_base_url.$path,
        );
    }

    private function post(PendingRequest $request, string $url): Response
    {
        try {
            return $request->post($url);
        } catch (Throwable $exception) {
            throw new ManagedAuthRefused(
                $exception->getMessage(),
                previous: $exception,
                recordsFailedAttempt: true,
            );
        }
    }

    /** @return array<string, mixed> */
    private function payload(Response $response): array
    {
        $payload = $response->json();
        $retryAfter = $this->retryAfter($response);

        if (! is_array($payload) || ($payload['contract_version'] ?? null) !== self::CONTRACT_VERSION) {
            throw new ManagedAuthRefused(retryAfterSeconds: $retryAfter, recordsFailedAttempt: true);
        }

        if ($response->status() !== 200) {
            $errors = [
                400 => ['invalid_grant', 'unsupported_contract_version', 'invalid_transition'],
                401 => ['invalid_client'],
                409 => ['idempotency_conflict', 'roster_changed', 'transition_state_conflict', 'transition_in_progress'],
                429 => ['rate_limited'],
                500 => ['server_error'],
                503 => ['server_error'],
            ];
            $error = $payload['error'] ?? null;

            throw new ManagedAuthRefused(
                is_string($error) && in_array($error, $errors[$response->status()] ?? [], true) ? $error : '',
                retryAfterSeconds: $retryAfter,
                recordsFailedAttempt: true,
            );
        }

        return $payload;
    }

    /** @param array<string, mixed> $payload */
    private function binding(array $payload, ManagedTransition $transition, int $generation): void
    {
        foreach ([
            'issuer' => $transition->issuer,
            'connection_id' => $transition->connection_id,
            'organization_id' => $transition->organization_id,
            'installation_id' => $transition->installation_id,
            'authority_generation' => $generation,
        ] as $field => $expected) {
            if (($payload[$field] ?? null) !== $expected) {
                throw new ManagedAuthRefused;
            }
        }

        $this->unsignedInteger($payload, 'roster_version');
        $this->unsignedInteger($payload, 'response_sequence');
        $this->dateString($payload, 'responded_at');
    }

    /** @param array<string, mixed> $payload */
    private function boundSnapshotState(
        array $payload,
        ManagedTransition $transition,
        string $status,
    ): ManagedTransitionAuthorityState {
        $rosterVersion = $this->unsignedInteger($payload, 'roster_version');
        $cutoff = $this->dateString($payload, 'roster_cutoff_at');

        if (($payload['transition_id'] ?? null) !== $transition->transition_id
            || $this->requiredEnum($payload, 'status', [$status]) !== $status
            || $rosterVersion !== $transition->roster_version
            || $cutoff !== $transition->roster_cutoff_at) {
            throw new ManagedAuthRefused;
        }

        return new ManagedTransitionAuthorityState(
            null,
            $transition->transition_id,
            null,
            $status,
            $rosterVersion,
            $cutoff,
            null,
            $status === 'acknowledged' ? $transition->generation_after : $transition->generation_before,
            null,
            null,
        );
    }

    /** @param array<string, mixed> $payload */
    private function member(array $payload): ManagedTransitionRosterMember
    {
        $displayName = $payload['display_name'] ?? null;
        $email = $this->requiredString($payload, 'contact_email', 255);
        $verified = $payload['contact_email_verified'] ?? null;

        if (! is_string($displayName)
            || strlen($displayName) > 255
            || filter_var($email, FILTER_VALIDATE_EMAIL) === false
            || ! is_bool($verified)) {
            throw new ManagedAuthRefused;
        }

        return new ManagedTransitionRosterMember(
            $this->requiredString($payload, 'scalpels_id', 255),
            $this->requiredEnum($payload, 'membership_status', ['active', 'removed', 'disabled']),
            $this->requiredEnum($payload, 'role', ['owner', 'admin', 'member']),
            $displayName,
            $email,
            $verified,
        );
    }

    private function requiredTransitionSnapshot(ManagedTransition $transition): void
    {
        if (! is_string($transition->transition_id) || $transition->transition_id === ''
            || strlen($transition->transition_id) > 255
            || ! is_int($transition->roster_version)
            || ! is_string($transition->roster_cutoff_at)
            || $transition->roster_cutoff_at === '') {
            throw new ManagedAuthRefused;
        }
    }

    private function requiredRecordedRequest(?string $body, ?string $digest): string
    {
        if ($body === null || $digest === null || strlen($digest) !== 64) {
            throw new ManagedAuthRefused;
        }

        return $body;
    }

    /** @param array<string, mixed> $payload */
    private function requiredString(array $payload, string $field, int $max): string
    {
        $value = $payload[$field] ?? null;
        if (! is_string($value) || $value === '' || strlen($value) > $max) {
            throw new ManagedAuthRefused;
        }

        return $value;
    }

    /** @param array<string, mixed> $payload */
    private function nullableString(array $payload, string $field, int $max, bool $allowsEmpty = false): ?string
    {
        if (! array_key_exists($field, $payload)) {
            throw new ManagedAuthRefused;
        }

        $value = $payload[$field];
        if ($value === null) {
            return null;
        }

        if (! is_string($value) || (! $allowsEmpty && $value === '') || strlen($value) > $max) {
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
        $value = $this->requiredString($payload, $field, 255);
        if (! in_array($value, $allowed, true)) {
            throw new ManagedAuthRefused;
        }

        return $value;
    }

    /**
     * @param  array<string, mixed>  $payload
     * @param  list<string>  $allowed
     */
    private function nullableEnum(array $payload, string $field, array $allowed): ?string
    {
        $value = $this->nullableString($payload, $field, 255);
        if ($value !== null && ! in_array($value, $allowed, true)) {
            throw new ManagedAuthRefused;
        }

        return $value;
    }

    /** @param array<string, mixed> $payload */
    private function unsignedInteger(array $payload, string $field): int
    {
        $value = $payload[$field] ?? null;
        if (! is_int($value) || $value < 0 || $value > self::MAX_SAFE_INTEGER) {
            throw new ManagedAuthRefused;
        }

        return $value;
    }

    /** @param array<string, mixed> $payload */
    private function dateString(array $payload, string $field): string
    {
        return $this->validDate($this->requiredString($payload, $field, 64));
    }

    /** @param array<string, mixed> $payload */
    private function nullableDateString(array $payload, string $field): ?string
    {
        $value = $this->nullableString($payload, $field, 64);

        return $value === null ? null : $this->validDate($value);
    }

    private function validDate(string $value): string
    {
        if (preg_match(
            '/\A(\d{4})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])[Tt](?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d+)?(?:[Zz]|[+-](?:[01]\d|2[0-3]):[0-5]\d)\z/D',
            $value,
            $parts,
        ) !== 1 || ! checkdate((int) $parts[2], (int) $parts[3], (int) $parts[1])) {
            throw new ManagedAuthRefused;
        }

        try {
            new DateTimeImmutable($value);
        } catch (Throwable) {
            throw new ManagedAuthRefused;
        }

        return $value;
    }

    /** @param array<string, mixed> $payload */
    private function serialize(array $payload): string
    {
        return json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }

    private function retryAfter(Response $response): ?int
    {
        $value = trim($response->header('Retry-After'));

        return $value !== '' && ctype_digit($value) ? min((int) $value, 300) : null;
    }
}
