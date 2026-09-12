<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Exceptions\ManagedAuthRefused;
use Illuminate\Database\QueryException;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Throwable;

final class ManagedTransitions
{
    private const string CREDENTIAL_REFERENCE = 'built-for-cloud.managed.client_secret';

    private const int MAX_SAFE_INTEGER = 9_007_199_254_740_991;

    public function __construct(private readonly Factory $http) {}

    public function prepare(User $actor, ManagedTransitionDirection $direction): ManagedTransition
    {
        $snapshot = $this->connectionSnapshot();
        $transitionRequestId = $this->randomKey();
        $body = $this->serialize([
            'connection_id' => $snapshot['connection_id'],
            'installation_id' => $snapshot['installation_id'],
            'direction' => $direction->value,
            'transition_request_id' => $transitionRequestId,
        ]);

        $transition = DB::transaction(function () use (
            $actor,
            $direction,
            $snapshot,
            $transitionRequestId,
            $body,
        ): ManagedTransition {
            $this->assertSnapshotCurrent($snapshot);
            $this->assertOwnerUser($actor, true);

            if (ManagedTransition::query()
                ->where('installation_id', $snapshot['installation_id'])
                ->whereNotIn('status', [
                    ManagedTransitionStatus::Acknowledged->value,
                    ManagedTransitionStatus::Abandoned->value,
                ])->exists()) {
                throw new ManagedAuthRefused('transition_in_progress');
            }

            if ($snapshot['authority_mode'] !== $direction->modeBefore()->value) {
                throw new ManagedAuthRefused;
            }

            return ManagedTransition::createActive([
                'id' => (string) Str::uuid(),
                'initiated_by_user_id' => (string) $actor->getKey(),
                'direction' => $direction,
                'status' => ManagedTransitionStatus::Preparing,
                'issuer' => $snapshot['issuer'],
                'connection_id' => $snapshot['connection_id'],
                'organization_id' => $snapshot['organization_id'],
                'installation_id' => $snapshot['installation_id'],
                'authority_base_url' => $snapshot['authority_base_url'],
                'authority_ca_bundle' => $snapshot['authority_ca_bundle'],
                'client_credential_reference' => $snapshot['client_credential_reference'],
                'mode_before' => $direction->modeBefore()->value,
                'mode_after' => $direction->modeAfter()->value,
                'generation_before' => $snapshot['authority_generation'],
                'generation_after' => $snapshot['authority_generation'] + 1,
                'transition_request_id' => $transitionRequestId,
                'prepare_request_body' => $body,
                'prepare_body_digest' => hash('sha256', $body),
            ]);
        });

        return $this->applyPrepared($transition, $this->client($transition)->prepare());
    }

    public function fetchRoster(ManagedTransition $transition): ManagedTransition
    {
        $transition = $this->fresh($transition, [ManagedTransitionStatus::Prepared]);
        $members = [];
        $cursors = [];
        $seenSubjects = [];
        $seenCursors = [];
        $cursor = null;
        $pageNumber = 0;

        while (true) {
            if ($pageNumber >= 200) {
                throw new ManagedAuthRefused;
            }

            if ($cursor !== null) {
                $hash = hash('sha256', "\x01".$cursor);
                if (isset($seenCursors[$hash])) {
                    throw new ManagedAuthRefused;
                }

                $seenCursors[$hash] = true;
                $cursors[] = ['cursor' => $cursor, 'cursor_hash' => $hash, 'first_seen_page' => $pageNumber + 1];
            }

            $pageNumber++;
            $page = $this->client($transition)->roster($cursor);

            foreach ($page->members as $position => $member) {
                if (isset($seenSubjects[$member->scalpelsId])) {
                    throw new ManagedAuthRefused;
                }

                $seenSubjects[$member->scalpelsId] = true;
                $members[] = [
                    ...$member->toArray(),
                    'ordinal' => count($members),
                    'page_number' => $pageNumber,
                    'page_position' => $position,
                ];
            }

            $cursor = $page->nextCursor;
            if ($cursor === null) {
                break;
            }
        }

        if (count($seenSubjects) !== $transition->roster_total) {
            throw new ManagedAuthRefused;
        }

        return DB::transaction(function () use ($transition, $members, $cursors, $pageNumber): ManagedTransition {
            $locked = $this->locked($transition, [ManagedTransitionStatus::Prepared]);
            $now = now();

            foreach ($members as $member) {
                DB::table('bfc_managed_transition_roster_members')->insert([
                    'id' => (string) Str::uuid(),
                    'managed_transition_id' => $locked->id,
                    ...$member,
                    'created_at' => $now,
                ]);
            }

            foreach ($cursors as $cursor) {
                // These rows preserve pagination evidence; the in-memory seen set enforces this completed pull.
                DB::table('bfc_managed_transition_roster_cursors')->insert([
                    'id' => (string) Str::uuid(),
                    'managed_transition_id' => $locked->id,
                    ...$cursor,
                    'created_at' => $now,
                ]);
            }

            $locked->forceFill([
                'status' => ManagedTransitionStatus::Rostered,
                'roster_pages_received' => $pageNumber,
                'roster_members_received' => count($members),
                'next_roster_cursor' => null,
            ])->save();

            return $locked->refresh();
        });
    }

    public function proposeDefault(ManagedTransition $transition): ManagedTransition
    {
        $transition = $this->fresh($transition, [ManagedTransitionStatus::Rostered]);
        $roster = DB::table('bfc_managed_transition_roster_members')
            ->where('managed_transition_id', $transition->id)
            ->orderBy('ordinal')
            ->get(['scalpels_id', 'role', 'contact_email']);
        $users = User::query()->orderBy('id')->get([
            'id', 'email', 'normalized_email', 'role', 'scalpels_issuer', 'scalpels_connection_id', 'scalpels_id',
        ]);
        $invitations = Invitation::query()
            ->pending()
            ->orderBy('created_at')
            ->get(['id']);
        $mapping = [];
        $linkedUsers = [];
        $reservedEmails = $users->pluck('normalized_email')->filter()->flip()->all();

        if ($transition->direction === ManagedTransitionDirection::Adopt) {
            foreach ($roster as $member) {
                $matched = $users->first(static fn (User $user): bool => $user->scalpels_issuer === $transition->issuer
                    && $user->scalpels_connection_id === $transition->connection_id
                    && $user->scalpels_id === $member->scalpels_id);

                if ($matched instanceof User) {
                    $linkedUsers[(string) $matched->getKey()] = true;
                    $mapping[] = [
                        'scalpels_id' => $member->scalpels_id,
                        'local_kind' => 'user',
                        'local_id' => (string) $matched->getKey(),
                        'role' => $member->role,
                        'disposition' => 'link',
                        'final_email' => $matched->email,
                    ];

                    continue;
                }

                $normalized = strtolower((string) $member->contact_email);
                $create = ! isset($reservedEmails[$normalized]);
                if ($create) {
                    $reservedEmails[$normalized] = true;
                }
                $mapping[] = [
                    'scalpels_id' => $member->scalpels_id,
                    'local_kind' => null,
                    'local_id' => null,
                    'role' => $create ? $member->role : null,
                    'disposition' => $create ? 'create' : 'defer_to_managed_jit',
                    'final_email' => $create ? $member->contact_email : null,
                ];
            }

            foreach ($users as $user) {
                if (! isset($linkedUsers[(string) $user->getKey()])) {
                    $mapping[] = $this->unmatchedLocalElement('user', (string) $user->getKey(), 'exclude');
                }
            }

            foreach ($invitations as $invitation) {
                $mapping[] = $this->unmatchedLocalElement('invitation', (string) $invitation->id, 'exclude');
            }
        } else {
            $rosterBySubject = $roster->keyBy('scalpels_id');

            foreach ($users as $user) {
                $member = $user->scalpels_issuer === $transition->issuer
                    && $user->scalpels_connection_id === $transition->connection_id
                    && is_string($user->scalpels_id)
                        ? $rosterBySubject->get($user->scalpels_id)
                        : null;
                $mapping[] = is_object($member)
                    ? [
                        'scalpels_id' => $member->scalpels_id,
                        'local_kind' => 'user',
                        'local_id' => (string) $user->getKey(),
                        'role' => $user->role,
                        'disposition' => 'link',
                        'final_email' => $user->email,
                    ]
                    : [
                        'scalpels_id' => null,
                        'local_kind' => 'user',
                        'local_id' => (string) $user->getKey(),
                        'role' => $user->role,
                        'disposition' => 'retain_local',
                        'final_email' => $user->email,
                    ];
            }

            foreach ($invitations as $invitation) {
                $mapping[] = $this->unmatchedLocalElement('invitation', (string) $invitation->id, 'retain_local');
            }
        }

        return $this->propose($transition, $mapping);
    }

    /** @param list<array<string, mixed>> $mapping */
    public function propose(ManagedTransition $transition, array $mapping): ManagedTransition
    {
        $transition = $this->fresh($transition, [
            ManagedTransitionStatus::Rostered,
            ManagedTransitionStatus::Proposed,
        ]);

        return $this->persistProposal($transition, $mapping);
    }

    /** @param list<array<string, mixed>> $mapping */
    public function proposeForOwner(User $actor, ManagedTransition $transition, array $mapping): ManagedTransition
    {
        $transition = $this->fresh($transition, [
            ManagedTransitionStatus::Rostered,
            ManagedTransitionStatus::Proposed,
        ]);

        return $this->persistProposal($transition, $mapping, $actor);
    }

    /**
     * @param  list<array<string, mixed>>  $mapping
     */
    private function persistProposal(
        ManagedTransition $transition,
        array $mapping,
        ?User $actor = null,
    ): ManagedTransition {
        return DB::transaction(function () use ($transition, $mapping, $actor): ManagedTransition {
            $locked = $this->locked($transition, [
                ManagedTransitionStatus::Rostered,
                ManagedTransitionStatus::Proposed,
            ]);
            if ($actor instanceof User) {
                $this->assertOwnerUser($actor, true);
            }
            $validated = $this->validateMapping($locked, $mapping);
            DB::table('bfc_managed_transition_mappings')
                ->where('managed_transition_id', $locked->id)
                ->delete();
            $now = now();

            foreach ($validated as $ordinal => $element) {
                DB::table('bfc_managed_transition_mappings')->insert([
                    'id' => (string) Str::uuid(),
                    'managed_transition_id' => $locked->id,
                    'ordinal' => $ordinal,
                    ...$element,
                    'created_at' => $now,
                    'updated_at' => $now,
                ]);
            }

            $locked->forceFill(['status' => ManagedTransitionStatus::Proposed])->save();

            return $locked->refresh();
        });
    }

    public function stage(ManagedTransition $transition): ManagedTransition
    {
        $transition = DB::transaction(function () use ($transition): ManagedTransition {
            $locked = $this->locked($transition, [ManagedTransitionStatus::Proposed]);
            $this->assertLocalAuthority($locked, false, true);
            $mapping = DB::table('bfc_managed_transition_mappings')
                ->where('managed_transition_id', $locked->id)
                ->orderBy('ordinal')
                ->get(['scalpels_id', 'local_kind', 'local_id', 'role', 'disposition', 'final_email'])
                ->map(static fn (object $row): array => (array) $row)
                ->all();
            $mapping = $this->validateMapping($locked, $mapping);
            $key = $this->randomKey();
            $body = $this->serialize([
                'connection_id' => $locked->connection_id,
                'installation_id' => $locked->installation_id,
                'idempotency_key' => $key,
                'roster_version' => $locked->roster_version,
                'roster_cutoff_at' => $locked->roster_cutoff_at,
                'mapping' => $mapping,
            ]);
            $locked->forceFill([
                'status' => ManagedTransitionStatus::Staging,
                'stage_idempotency_key' => $key,
                'stage_request_body' => $body,
                'stage_body_digest' => hash('sha256', $body),
            ])->save();

            return $locked->refresh();
        });

        $this->client($transition)->stage();

        return $this->advance($transition, ManagedTransitionStatus::Staging, ManagedTransitionStatus::Staged);
    }

    /**
     * P4d supplies the local effects callback. The transition checkpoint commits in that same transaction.
     *
     * @param  callable(ManagedTransition): void  $effects
     */
    public function commit(ManagedTransition $transition, callable $effects): ManagedTransition
    {
        return DB::transaction(function () use ($transition, $effects): ManagedTransition {
            $locked = $this->locked($transition, [ManagedTransitionStatus::Staged]);
            if ($locked->abandon_idempotency_key !== null) {
                throw new ManagedAuthRefused('transition_state_conflict');
            }

            $authority = DB::table('bfc_authority')
                ->where('key', InstallationAuthority::KEY)
                ->lockForUpdate()
                ->first(['mode', 'generation', 'installation_id']);
            if (! is_object($authority)
                || $authority->mode !== $locked->mode_before
                || $authority->generation !== $locked->generation_before
                || $authority->installation_id !== $locked->installation_id) {
                throw new ManagedAuthRefused('transition_state_conflict');
            }

            $effects($locked);
            $this->assertLocalAuthority($locked, true, false);
            $locked->forceFill([
                'status' => ManagedTransitionStatus::Committed,
                'local_commit_receipt' => $this->randomKey(),
            ])->save();

            return $locked->refresh();
        });
    }

    public function acknowledge(ManagedTransition $transition): ManagedTransition
    {
        $transition = DB::transaction(function () use ($transition): ManagedTransition {
            $locked = $this->locked($transition, [ManagedTransitionStatus::Committed]);
            $this->assertLocalAuthority($locked, true, true);
            if (! is_string($locked->local_commit_receipt) || $locked->local_commit_receipt === '') {
                throw new ManagedAuthRefused;
            }

            $key = $this->randomKey();
            $body = $this->serialize([
                'connection_id' => $locked->connection_id,
                'installation_id' => $locked->installation_id,
                'idempotency_key' => $key,
                'local_commit_receipt' => $locked->local_commit_receipt,
                'mode_after' => $locked->mode_after,
                'generation_after' => $locked->generation_after,
            ]);
            $locked->forceFill([
                'status' => ManagedTransitionStatus::Acknowledging,
                'ack_idempotency_key' => $key,
                'ack_request_body' => $body,
                'ack_body_digest' => hash('sha256', $body),
            ])->save();

            return $locked->refresh();
        });

        return $this->applyAcknowledged($transition, $this->client($transition)->acknowledge());
    }

    public function recover(ManagedTransition $transition): ManagedTransition
    {
        $transition = $this->fresh($transition, [
            ManagedTransitionStatus::Preparing,
            ManagedTransitionStatus::Prepared,
            ManagedTransitionStatus::Rostered,
            ManagedTransitionStatus::Proposed,
            ManagedTransitionStatus::Staging,
            ManagedTransitionStatus::Staged,
            ManagedTransitionStatus::Committed,
            ManagedTransitionStatus::Acknowledging,
            ManagedTransitionStatus::Acknowledged,
            ManagedTransitionStatus::Abandoned,
        ]);

        if (in_array($transition->status, [
            ManagedTransitionStatus::Acknowledged,
            ManagedTransitionStatus::Abandoned,
        ], true)) {
            return $transition;
        }

        $this->assertLocalAuthority(
            $transition,
            in_array($transition->status, [
                ManagedTransitionStatus::Committed,
                ManagedTransitionStatus::Acknowledging,
            ], true),
            false,
        );

        if ($transition->status === ManagedTransitionStatus::Preparing) {
            $recovered = $this->client($transition)->recoverRequest();
            if ($recovered->status === null || $recovered->status === 'abandoned') {
                return $this->advance($transition, ManagedTransitionStatus::Preparing, ManagedTransitionStatus::Abandoned);
            }

            if ($recovered->status !== 'prepared') {
                throw new ManagedAuthRefused;
            }

            $prepared = $this->client($transition)->prepare();

            if ($recovered->transitionId !== $prepared->transitionId) {
                throw new ManagedAuthRefused;
            }

            return $this->applyPrepared($transition, $prepared);
        }

        $authority = $this->client($transition)->state();

        if ($authority->status === 'abandoned') {
            return $this->advanceFromAnyPreCommit($transition, ManagedTransitionStatus::Abandoned);
        }

        if ($authority->status === 'acknowledged') {
            if (! in_array($transition->status, [
                ManagedTransitionStatus::Committed,
                ManagedTransitionStatus::Acknowledging,
            ], true)) {
                throw new ManagedAuthRefused;
            }

            return $this->applyAcknowledged($transition, $authority);
        }

        if ($authority->status === 'staged') {
            if ($transition->status === ManagedTransitionStatus::Staging) {
                return $this->advance($transition, ManagedTransitionStatus::Staging, ManagedTransitionStatus::Staged);
            }

            if ($transition->status === ManagedTransitionStatus::Committed) {
                return $this->acknowledge($transition);
            }

            if ($transition->status === ManagedTransitionStatus::Acknowledging) {
                return $this->applyAcknowledged($transition, $this->client($transition)->acknowledge());
            }

            if ($transition->status !== ManagedTransitionStatus::Staged) {
                throw new ManagedAuthRefused;
            }

            return $transition;
        }

        if ($authority->status !== 'prepared') {
            throw new ManagedAuthRefused;
        }

        if ($transition->status === ManagedTransitionStatus::Staging) {
            $this->assertStageMappingCurrent($transition);
            $this->client($transition)->stage();

            return $this->advance($transition, ManagedTransitionStatus::Staging, ManagedTransitionStatus::Staged);
        }

        if (! in_array($transition->status, [
            ManagedTransitionStatus::Prepared,
            ManagedTransitionStatus::Rostered,
            ManagedTransitionStatus::Proposed,
        ], true)) {
            throw new ManagedAuthRefused;
        }

        return $transition;
    }

    private function assertStageMappingCurrent(ManagedTransition $transition): void
    {
        if (! is_string($transition->stage_request_body) || $transition->stage_request_body === '') {
            throw new ManagedAuthRefused;
        }

        try {
            $payload = json_decode($transition->stage_request_body, true, flags: JSON_THROW_ON_ERROR);
        } catch (Throwable $exception) {
            throw new ManagedAuthRefused(previous: $exception);
        }

        if (! is_array($payload) || ! is_array($payload['mapping'] ?? null)) {
            throw new ManagedAuthRefused;
        }

        $this->validateMapping($transition, $payload['mapping']);
    }

    public function abandon(Request $request, ManagedTransition $transition): ManagedTransition
    {
        $this->assertOwnerRequest($request, false);
        $transition = $this->fresh($transition, [
            ManagedTransitionStatus::Prepared,
            ManagedTransitionStatus::Rostered,
            ManagedTransitionStatus::Proposed,
            ManagedTransitionStatus::Staging,
            ManagedTransitionStatus::Staged,
        ]);
        $this->assertLocalAuthority($transition, false, false);
        $authority = $this->client($transition)->state();

        if ($authority->status === 'abandoned') {
            return $this->advanceFromAnyPreCommit($transition, ManagedTransitionStatus::Abandoned);
        }

        $expectedAuthorityStatuses = match ($transition->status) {
            ManagedTransitionStatus::Staging => ['prepared', 'staged'],
            ManagedTransitionStatus::Staged => ['staged'],
            default => ['prepared'],
        };
        if (! in_array($authority->status, $expectedAuthorityStatuses, true)) {
            throw new ManagedAuthRefused('transition_state_conflict');
        }

        $transition = DB::transaction(function () use ($request, $transition): ManagedTransition {
            $this->assertOwnerRequest($request, true);
            $locked = $this->locked($transition, [
                ManagedTransitionStatus::Prepared,
                ManagedTransitionStatus::Rostered,
                ManagedTransitionStatus::Proposed,
                ManagedTransitionStatus::Staging,
                ManagedTransitionStatus::Staged,
            ]);

            if ($locked->abandon_idempotency_key === null) {
                $key = $this->randomKey();
                $body = $this->serialize([
                    'connection_id' => $locked->connection_id,
                    'installation_id' => $locked->installation_id,
                    'idempotency_key' => $key,
                ]);
                $locked->forceFill([
                    'abandon_idempotency_key' => $key,
                    'abandon_request_body' => $body,
                    'abandon_body_digest' => hash('sha256', $body),
                ])->save();
            }

            return $locked->refresh();
        });

        $this->client($transition)->abandon();

        return $this->advanceFromAnyPreCommit($transition, ManagedTransitionStatus::Abandoned);
    }

    private function applyPrepared(
        ManagedTransition $transition,
        ManagedTransitionAuthorityState $authority,
    ): ManagedTransition {
        if ($authority->status !== 'prepared'
            || $authority->transitionId === null
            || $authority->rosterCutoffAt === null
            || $authority->rosterTotal === null) {
            throw new ManagedAuthRefused;
        }

        try {
            return DB::transaction(function () use ($transition, $authority): ManagedTransition {
                $locked = $this->locked($transition, [ManagedTransitionStatus::Preparing]);
                $locked->forceFill([
                    'status' => ManagedTransitionStatus::Prepared,
                    'transition_id' => $authority->transitionId,
                    'roster_version' => $authority->rosterVersion,
                    'roster_cutoff_at' => $authority->rosterCutoffAt,
                    'roster_total' => $authority->rosterTotal,
                ])->save();

                return $locked->refresh();
            });
        } catch (QueryException $exception) {
            throw new ManagedAuthRefused(previous: $exception);
        }
    }

    private function applyAcknowledged(
        ManagedTransition $transition,
        ManagedTransitionAuthorityState $authority,
    ): ManagedTransition {
        if ($authority->status !== 'acknowledged'
            || ! is_string($transition->local_commit_receipt)
            || $transition->local_commit_receipt === ''
            || ! is_string($authority->localCommitReceipt)
            || ! hash_equals($transition->local_commit_receipt, $authority->localCommitReceipt)
            || $authority->acknowledgedAt === null) {
            throw new ManagedAuthRefused;
        }

        return DB::transaction(function () use ($transition, $authority): ManagedTransition {
            $locked = $this->locked($transition, [
                ManagedTransitionStatus::Committed,
                ManagedTransitionStatus::Acknowledging,
            ]);
            $locked->forceFill([
                'status' => ManagedTransitionStatus::Acknowledged,
                'authority_acknowledged_at' => $authority->acknowledgedAt,
            ])->save();

            return $locked->refresh();
        });
    }

    private function advance(
        ManagedTransition $transition,
        ManagedTransitionStatus $from,
        ManagedTransitionStatus $to,
    ): ManagedTransition {
        return DB::transaction(function () use ($transition, $from, $to): ManagedTransition {
            $locked = $this->locked($transition, [$from]);
            $locked->forceFill(['status' => $to])->save();

            return $locked->refresh();
        });
    }

    private function advanceFromAnyPreCommit(
        ManagedTransition $transition,
        ManagedTransitionStatus $to,
    ): ManagedTransition {
        return DB::transaction(function () use ($transition, $to): ManagedTransition {
            $locked = $this->locked($transition, [
                ManagedTransitionStatus::Prepared,
                ManagedTransitionStatus::Rostered,
                ManagedTransitionStatus::Proposed,
                ManagedTransitionStatus::Staging,
                ManagedTransitionStatus::Staged,
            ]);
            $locked->forceFill(['status' => $to])->save();

            return $locked->refresh();
        });
    }

    /** @param list<ManagedTransitionStatus> $statuses */
    private function fresh(ManagedTransition $transition, array $statuses): ManagedTransition
    {
        if (! $transition->exists) {
            throw new ManagedAuthRefused;
        }

        $fresh = ManagedTransition::query()->find($transition->getKey());
        if (! $fresh instanceof ManagedTransition
            || $fresh->status !== $transition->status
            || ! in_array($fresh->status, $statuses, true)) {
            throw new ManagedAuthRefused('transition_state_conflict');
        }

        return $fresh;
    }

    /** @param list<ManagedTransitionStatus> $statuses */
    private function locked(ManagedTransition $transition, array $statuses): ManagedTransition
    {
        $locked = ManagedTransition::query()->whereKey($transition->getKey())->lockForUpdate()->first();
        if (! $locked instanceof ManagedTransition
            || $locked->status !== $transition->status
            || ! in_array($locked->status, $statuses, true)) {
            throw new ManagedAuthRefused('transition_state_conflict');
        }

        return $locked;
    }

    /**
     * @param  list<array<string, mixed>>  $mapping
     * @return list<array{scalpels_id: ?string, local_kind: ?string, local_id: ?string, role: ?string, disposition: string, final_email: ?string}>
     */
    private function validateMapping(ManagedTransition $transition, array $mapping): array
    {
        $roster = DB::table('bfc_managed_transition_roster_members')
            ->where('managed_transition_id', $transition->id)
            ->get(['scalpels_id', 'role'])
            ->keyBy('scalpels_id');
        $users = User::query()->get(['id', 'email', 'scalpels_issuer', 'scalpels_connection_id', 'scalpels_id'])->keyBy(
            static fn (User $user): string => (string) $user->getKey(),
        );
        $invitations = Invitation::query()
            ->pending()
            ->get(['id', 'email'])
            ->keyBy(static fn (Invitation $invitation): string => (string) $invitation->getKey());
        $validated = [];
        $seenSubjects = [];
        $seenLocal = [];

        foreach ($mapping as $element) {
            if (! is_array($element)) {
                throw new ManagedAuthRefused;
            }

            $keys = array_keys($element);
            sort($keys);
            if ($keys !== ['disposition', 'final_email', 'local_id', 'local_kind', 'role', 'scalpels_id']) {
                throw new ManagedAuthRefused;
            }

            $subject = $this->nullableInputString($element['scalpels_id'], 255);
            $kind = $this->nullableInputEnum($element['local_kind'], ['user', 'invitation']);
            $localId = $this->nullableInputString($element['local_id'], 64);
            $role = $this->nullableInputEnum($element['role'], ['owner', 'admin', 'member']);
            $disposition = $this->requiredInputEnum($element['disposition'], [
                'link', 'create', 'retain_local', 'exclude', 'defer_to_managed_jit',
            ]);
            $email = $this->nullableInputString($element['final_email'], 255);
            $shape = [$kind, $subject !== null, $localId !== null, $role !== null, $email !== null];
            $legal = match ($disposition) {
                'link' => in_array($shape, [
                    ['user', true, true, true, true],
                    ['invitation', true, true, true, true],
                ], true),
                'create' => $shape === [null, true, false, true, true],
                'retain_local' => in_array($shape, [
                    ['user', false, true, true, true],
                    ['invitation', false, true, false, false],
                ], true),
                'exclude' => in_array($shape, [
                    ['user', false, true, false, false],
                    ['invitation', false, true, false, false],
                ], true),
                'defer_to_managed_jit' => $shape === [null, true, false, false, false],
                default => false,
            };

            if (! $legal
                || ($email !== null && filter_var($email, FILTER_VALIDATE_EMAIL) === false)
                || ($transition->direction === ManagedTransitionDirection::Adopt
                    && in_array($disposition, ['retain_local'], true))
                || ($transition->direction === ManagedTransitionDirection::Exit
                    && in_array($disposition, ['create', 'defer_to_managed_jit'], true))) {
                throw new ManagedAuthRefused;
            }

            if ($subject !== null) {
                if (isset($seenSubjects[$subject]) || ! $roster->has($subject)) {
                    throw new ManagedAuthRefused;
                }

                $seenSubjects[$subject] = true;
                $rosterMember = $roster->get($subject);
                if ($transition->direction === ManagedTransitionDirection::Adopt
                    && in_array($disposition, ['link', 'create'], true)
                    && is_object($rosterMember)
                    && $role !== $rosterMember->role) {
                    throw new ManagedAuthRefused('roster_changed');
                }
            }

            if ($localId !== null && $kind !== null) {
                $localKey = $kind.':'.$localId;
                if (isset($seenLocal[$localKey])) {
                    throw new ManagedAuthRefused;
                }

                $seenLocal[$localKey] = true;
                if ($kind === 'invitation' && ! $invitations->has($localId)) {
                    throw new ManagedAuthRefused;
                }

                if ($kind === 'user') {
                    $user = $users->get($localId);
                    if (! $user instanceof User
                        || ($user->scalpels_id !== null
                            && ($user->scalpels_issuer !== $transition->issuer
                                || $user->scalpels_connection_id !== $transition->connection_id
                                || ($subject !== null && $user->scalpels_id !== $subject)))) {
                        throw new ManagedAuthRefused;
                    }
                }
            }

            $validated[] = [
                'scalpels_id' => $subject,
                'local_kind' => $kind,
                'local_id' => $localId,
                'role' => $role,
                'disposition' => $disposition,
                'final_email' => $email,
            ];
        }

        $expectedLocal = [
            ...$users->keys()->map(static fn (mixed $id): string => 'user:'.(string) $id)->all(),
            ...$invitations->keys()->map(static fn (mixed $id): string => 'invitation:'.(string) $id)->all(),
        ];
        $actualLocal = array_keys($seenLocal);
        sort($expectedLocal);
        sort($actualLocal);

        if ($expectedLocal !== $actualLocal) {
            throw new ManagedAuthRefused;
        }

        if ($transition->direction === ManagedTransitionDirection::Adopt) {
            $expectedSubjects = $roster->keys()->map(static fn (mixed $id): string => (string) $id)->all();
            $actualSubjects = array_keys($seenSubjects);
            sort($expectedSubjects);
            sort($actualSubjects);
            if ($expectedSubjects !== $actualSubjects) {
                throw new ManagedAuthRefused;
            }
        }

        $projectedEmails = [];
        foreach ($validated as $element) {
            $email = null;
            if ($element['local_kind'] === 'user') {
                $user = $users->get($element['local_id']);
                if (! $user instanceof User) {
                    throw new ManagedAuthRefused;
                }

                $email = in_array($element['disposition'], ['link', 'retain_local'], true)
                    ? $element['final_email']
                    : $user->email;
            } elseif ($element['local_kind'] === 'invitation' && $element['disposition'] === 'retain_local') {
                $invitation = $invitations->get($element['local_id']);
                if (! $invitation instanceof Invitation) {
                    throw new ManagedAuthRefused;
                }

                $email = $invitation->email;
            } elseif ($element['disposition'] === 'create'
                || ($element['local_kind'] === 'invitation' && $element['disposition'] === 'link')) {
                $email = $element['final_email'];
            }

            if (is_string($email)) {
                $normalized = strtolower($email);
                if (isset($projectedEmails[$normalized])) {
                    throw new ManagedAuthRefused;
                }

                $projectedEmails[$normalized] = true;
            }
        }

        return $validated;
    }

    /**
     * @return array{scalpels_id: null, local_kind: string, local_id: string, role: null, disposition: string, final_email: null}
     */
    private function unmatchedLocalElement(string $kind, string $id, string $disposition): array
    {
        return [
            'scalpels_id' => null,
            'local_kind' => $kind,
            'local_id' => $id,
            'role' => null,
            'disposition' => $disposition,
            'final_email' => null,
        ];
    }

    /**
     * @return array{issuer: string, connection_id: string, organization_id: string, installation_id: string, authority_base_url: string, authority_ca_bundle: ?string, client_credential_reference: string, authority_generation: int, authority_mode: string}
     */
    private function connectionSnapshot(): array
    {
        $row = DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->first([
            'mode', 'generation', 'issuer', 'connection_id', 'organization_id', 'installation_id',
            'authority_base_url',
        ]);
        $caBundle = config('built-for-cloud.managed.ca_bundle');
        $secret = config(self::CREDENTIAL_REFERENCE);

        if (! is_object($row)
            || ! in_array($row->mode, [AuthorityMode::Standalone->value, AuthorityMode::Managed->value], true)
            || ! is_int($row->generation)
            || $row->generation < 1
            || $row->generation >= self::MAX_SAFE_INTEGER
            || ! $this->nonEmpty($row->issuer)
            || ! $this->nonEmpty($row->connection_id)
            || ! $this->nonEmpty($row->organization_id)
            || ! $this->nonEmpty($row->installation_id)
            || ! $this->validBaseUrl($row->authority_base_url)
            || ! $this->nonEmpty($secret)
            || ($caBundle !== null && ! $this->nonEmpty($caBundle))) {
            throw new ManagedAuthRefused;
        }

        return [
            'issuer' => $row->issuer,
            'connection_id' => $row->connection_id,
            'organization_id' => $row->organization_id,
            'installation_id' => $row->installation_id,
            'authority_base_url' => rtrim($row->authority_base_url, '/'),
            'authority_ca_bundle' => $caBundle,
            'client_credential_reference' => self::CREDENTIAL_REFERENCE,
            'authority_generation' => $row->generation,
            'authority_mode' => $row->mode,
        ];
    }

    private function assertOwnerRequest(Request $request, bool $lock): User
    {
        $actor = $request->user();
        if (! $actor instanceof User || ! StandaloneAccess::sessionVersionIsCurrent($request, $actor)) {
            throw new ManagedAuthRefused;
        }

        return $this->assertOwnerUser($actor, $lock);
    }

    private function assertOwnerUser(User $actor, bool $lock): User
    {
        $query = User::query()->whereKey($actor->getKey())->whereNotNull('owner_slot');
        if ($lock) {
            $query->lockForUpdate();
        }

        $current = $query->first();
        if (! $current instanceof User
            || $current->status !== 'active'
            || ! RolePolicy::canInitiateModeTransition($current->role)) {
            throw new ManagedAuthRefused;
        }

        return $current;
    }

    /**
     * @param  array{issuer: string, connection_id: string, organization_id: string, installation_id: string, authority_base_url: string, authority_ca_bundle: ?string, client_credential_reference: string, authority_generation: int, authority_mode: string}  $snapshot
     */
    private function assertSnapshotCurrent(array $snapshot): void
    {
        $row = DB::table('bfc_authority')
            ->where('key', InstallationAuthority::KEY)
            ->lockForUpdate()
            ->first([
                'mode', 'generation', 'issuer', 'connection_id', 'organization_id', 'installation_id',
                'authority_base_url',
            ]);

        if (! is_object($row)
            || $row->mode !== $snapshot['authority_mode']
            || $row->generation !== $snapshot['authority_generation']
            || $row->issuer !== $snapshot['issuer']
            || $row->connection_id !== $snapshot['connection_id']
            || $row->organization_id !== $snapshot['organization_id']
            || $row->installation_id !== $snapshot['installation_id']
            || rtrim((string) $row->authority_base_url, '/') !== $snapshot['authority_base_url']) {
            throw new ManagedAuthRefused('transition_state_conflict');
        }
    }

    private function assertLocalAuthority(ManagedTransition $transition, bool $after, bool $lock): void
    {
        $query = DB::table('bfc_authority')->where('key', InstallationAuthority::KEY);
        if ($lock) {
            $query->lockForUpdate();
        }

        $row = $query->first(['mode', 'generation', 'installation_id']);
        $mode = $after ? $transition->mode_after : $transition->mode_before;
        $generation = $after ? $transition->generation_after : $transition->generation_before;

        if (! is_object($row)
            || $row->mode !== $mode
            || $row->generation !== $generation
            || $row->installation_id !== $transition->installation_id) {
            throw new ManagedAuthRefused('transition_state_conflict');
        }
    }

    private function nullableInputString(mixed $value, int $max): ?string
    {
        if ($value === null) {
            return null;
        }

        if (! is_string($value) || $value === '' || strlen($value) > $max) {
            throw new ManagedAuthRefused;
        }

        return $value;
    }

    /** @param list<string> $allowed */
    private function nullableInputEnum(mixed $value, array $allowed): ?string
    {
        $value = $this->nullableInputString($value, 255);
        if ($value !== null && ! in_array($value, $allowed, true)) {
            throw new ManagedAuthRefused;
        }

        return $value;
    }

    /** @param list<string> $allowed */
    private function requiredInputEnum(mixed $value, array $allowed): string
    {
        $value = $this->nullableInputEnum($value, $allowed);
        if ($value === null) {
            throw new ManagedAuthRefused;
        }

        return $value;
    }

    /** @param array<string, mixed> $payload */
    private function serialize(array $payload): string
    {
        return json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }

    private function randomKey(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    private function nonEmpty(mixed $value): bool
    {
        return is_string($value) && $value !== '';
    }

    private function validBaseUrl(mixed $url): bool
    {
        if (! $this->nonEmpty($url)) {
            return false;
        }

        $parts = parse_url($url);

        return is_array($parts)
            && ($parts['scheme'] ?? null) === 'https'
            && $this->nonEmpty($parts['host'] ?? null)
            && ! array_key_exists('query', $parts)
            && ! array_key_exists('fragment', $parts)
            && ! array_key_exists('user', $parts)
            && ! array_key_exists('pass', $parts)
            && in_array($parts['path'] ?? '', ['', '/'], true);
    }

    private function client(ManagedTransition $transition): ManagedTransitionClient
    {
        return new ManagedTransitionClient($this->http, $transition);
    }
}
