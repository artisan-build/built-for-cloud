<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Exceptions\ManagedAuthRefused;
use ArtisanBuild\BuiltForCloud\Exceptions\ManagedOwnerAcquisitionNotApplicable;
use ArtisanBuild\BuiltForCloud\Exceptions\ManagedOwnerContested;
use Carbon\CarbonImmutable;
use Closure;
use Illuminate\Database\QueryException;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Throwable;

final class ManagedMembershipResponses
{
    public function __construct(
        private readonly ManagedIdentityUpsert $identities,
        private readonly ManagedAuthClient $client,
    ) {}

    public function applyConfirmation(
        ManagedAuthConnection $connection,
        User $subject,
        ManagedAuthConfirmation $response,
    ): bool {
        try {
            return $this->transaction(function () use ($connection, $subject, $response): bool {
                $authority = $this->lockedAuthority($connection);
                $user = User::query()->lockForUpdate()->find($subject->getKey());

                if (! ($user instanceof User)
                    || $user->scalpels_issuer !== $connection->issuer
                    || $user->scalpels_connection_id !== $connection->connectionId
                    || $user->scalpels_id !== $response->scalpelsId) {
                    throw new ManagedAuthRefused;
                }

                $receipt = CarbonImmutable::now();
                $membershipAccepted = $this->newer(
                    $user->managed_membership_generation,
                    $user->managed_membership_roster_version,
                    $user->managed_membership_response_sequence,
                    $connection->authorityGeneration,
                    $response->rosterVersion,
                    $response->responseSequence,
                );
                $connectionAccepted = $this->connectionAccepted($authority, $connection, $response);

                $this->assertRecognizedRole($response->role);
                $this->ownershipOutcome($user, $response, $membershipAccepted, false);

                if ($connectionAccepted) {
                    $this->storeConnectionDimension($response, $connection);
                }

                if ($membershipAccepted) {
                    $this->fillMembershipDimension($user, $response, $connection, $receipt);
                }

                $active = ($membershipAccepted
                    ? $response->membershipStatus
                    : $user->managed_membership_status) === 'active'
                    && $this->connectionStatus($authority, $response, $connectionAccepted) === 'active';
                $timestamps = [
                    'membership_checked_at' => $receipt,
                    'membership_response_at' => $receipt,
                ];

                if ($membershipAccepted && $active) {
                    $timestamps['membership_confirmed_at'] = $receipt;
                }

                $user->forceFill($timestamps)->save();
                $this->applyDenial(
                    $connection,
                    $user,
                    $membershipAccepted && $response->membershipStatus !== 'active',
                    $connectionAccepted && $response->connectionStatus === 'inactive',
                );

                return $active;
            });
        } catch (QueryException $exception) {
            $this->refuseOwnerSlotViolation($exception, $subject->getKey(), $response->scalpelsId);

            throw $exception;
        }
    }

    public function applyExchange(
        ManagedAuthConnection $connection,
        ManagedAuthExchange $response,
    ): ?User {
        if (! $response->contactEmailVerified) {
            return null;
        }

        if ($this->shouldAttemptOwnerAcquisition($connection, $response)) {
            try {
                return $this->applyOwnerAcquisition($connection, $response);
            } catch (ManagedOwnerAcquisitionNotApplicable) {
                // The ordinary authority-first path re-evaluates the response from current state.
            } catch (ManagedAuthRefused $exception) {
                $this->refuseOwnerSlotViolation($exception, null, $response->scalpelsId);

                throw $exception;
            }
        }

        try {
            return $this->applyExchangeOnce($connection, $response, true);
        } catch (ManagedOwnerContested) {
            try {
                $statement = $this->client->ownership($connection, $this->seatedOwnerScalpelsId());

                if (! $this->applyOwnershipStatement($connection, $statement)) {
                    throw new ManagedAuthRefused;
                }

                return $this->applyExchangeOnce($connection, $response, false);
            } catch (ManagedAuthRefused $exception) {
                throw new ManagedAuthRefused('managed_owner_transition_refused', previous: $exception);
            }
        }
    }

    private function applyExchangeOnce(
        ManagedAuthConnection $connection,
        ManagedAuthExchange $response,
        bool $mayPullOwnership,
    ): ?User {
        return $this->transaction(function () use ($connection, $response, $mayPullOwnership): ?User {
            $authority = $this->lockedAuthority($connection);
            $user = User::query()
                ->where('scalpels_issuer', $connection->issuer)
                ->where('scalpels_connection_id', $connection->connectionId)
                ->where('scalpels_id', $response->scalpelsId)
                ->lockForUpdate()
                ->first();
            $membershipAccepted = ! ($user instanceof User) || $this->newer(
                $user->managed_membership_generation,
                $user->managed_membership_roster_version,
                $user->managed_membership_response_sequence,
                $connection->authorityGeneration,
                $response->rosterVersion,
                $response->responseSequence,
            );
            $connectionAccepted = $this->connectionAccepted($authority, $connection, $response);

            $this->assertRecognizedRole($response->role);
            $this->ownershipOutcome($user, $response, $membershipAccepted, $mayPullOwnership);
            $receipt = CarbonImmutable::now();

            if ($connectionAccepted) {
                $this->storeConnectionDimension($response, $connection);
            }

            $active = ($membershipAccepted
                ? $response->membershipStatus
                : $user?->managed_membership_status) === 'active'
                && $this->connectionStatus($authority, $response, $connectionAccepted) === 'active';

            if (! $active) {
                // P3c-2 attaches AC10's subject-local and installation-wide blast radii here.
                if ($user instanceof User) {
                    if ($membershipAccepted) {
                        $this->fillMembershipDimension($user, $response, $connection, $receipt);
                    }

                    $user->forceFill([
                        'membership_checked_at' => $receipt,
                        'membership_response_at' => $receipt,
                    ])->save();
                }

                $this->applyDenial(
                    $connection,
                    $user,
                    $membershipAccepted && $response->membershipStatus !== 'active',
                    $connectionAccepted && $response->connectionStatus === 'inactive',
                );

                return null;
            }

            if (! $membershipAccepted) {
                return $user;
            }

            $user = $this->identities->upsert($connection, $response);
            $this->fillMembershipDimension($user, $response, $connection, $receipt);
            $user->save();

            return $user->refresh();
        });
    }

    private function shouldAttemptOwnerAcquisition(
        ManagedAuthConnection $connection,
        ManagedAuthExchange $response,
    ): bool {
        return $response->membershipStatus === 'active'
            && $response->connectionStatus === 'active'
            && $response->role === UserRole::Owner->value
            && ! User::query()
                ->where('scalpels_issuer', $connection->issuer)
                ->where('scalpels_connection_id', $connection->connectionId)
                ->where('scalpels_id', $response->scalpelsId)
                ->exists()
            && ! User::query()->whereNotNull('owner_slot')->exists();
    }

    private function applyOwnerAcquisition(
        ManagedAuthConnection $connection,
        ManagedAuthExchange $response,
    ): User {
        return $this->transaction(function () use ($connection, $response): User {
            $authority = $this->authority($connection, false);
            $user = User::query()
                ->where('scalpels_issuer', $connection->issuer)
                ->where('scalpels_connection_id', $connection->connectionId)
                ->where('scalpels_id', $response->scalpelsId)
                ->lockForUpdate()
                ->first();
            $membershipAccepted = ! ($user instanceof User) || $this->newer(
                $user->managed_membership_generation,
                $user->managed_membership_roster_version,
                $user->managed_membership_response_sequence,
                $connection->authorityGeneration,
                $response->rosterVersion,
                $response->responseSequence,
            );
            $connectionAccepted = $this->connectionAccepted($authority, $connection, $response);

            if (! $membershipAccepted
                || $this->connectionStatus($authority, $response, $connectionAccepted) !== 'active') {
                throw new ManagedOwnerAcquisitionNotApplicable;
            }

            $this->assertRecognizedRole($response->role);

            if (User::query()->whereNotNull('owner_slot')->lockForUpdate()->first() instanceof User) {
                throw new ManagedOwnerAcquisitionNotApplicable;
            }

            $receipt = CarbonImmutable::now();
            $user = $this->identities->upsert($connection, $response);
            $this->fillMembershipDimension($user, $response, $connection, $receipt);
            $user->save();

            // Acquisition writes the unique Owner slot before taking the authority lock, so a
            // concurrent first login is arbitrated by the database rather than this process.
            $authority = $this->lockedAuthority($connection);
            $connectionAccepted = $this->connectionAccepted($authority, $connection, $response);

            if ($this->connectionStatus($authority, $response, $connectionAccepted) !== 'active') {
                throw new ManagedOwnerAcquisitionNotApplicable;
            }

            if ($connectionAccepted) {
                $this->storeConnectionDimension($response, $connection);
            }

            return $user->refresh();
        });
    }

    public function applyOwnershipStatement(
        ManagedAuthConnection $connection,
        ManagedOwnershipStatement $statement,
    ): bool {
        $disposition = $this->ownershipStatementDisposition($statement);

        try {
            return $this->transaction(function () use ($connection, $statement, $disposition): bool {
                $authority = $this->lockedAuthority($connection);

                if (! $this->newer(
                    $this->nullableInt($authority->managed_ownership_generation),
                    $this->nullableInt($authority->managed_ownership_roster_version),
                    $this->nullableInt($authority->managed_ownership_response_sequence),
                    $connection->authorityGeneration,
                    $statement->rosterVersion,
                    $statement->responseSequence,
                )) {
                    return false;
                }

                $incumbent = User::query()->whereNotNull('owner_slot')->lockForUpdate()->first();
                $expectedIncumbentId = $statement->seatedOwner?->scalpelsId;

                if (! $this->incumbentMatches($incumbent, $connection, $expectedIncumbentId)) {
                    throw new ManagedAuthRefused;
                }

                $incoming = $incumbent instanceof User
                    && $incumbent->scalpels_id === $statement->owner->scalpelsId
                    ? $incumbent
                    : User::query()
                        ->where('scalpels_issuer', $connection->issuer)
                        ->where('scalpels_connection_id', $connection->connectionId)
                        ->where('scalpels_id', $statement->owner->scalpelsId)
                        ->lockForUpdate()
                        ->first();

                if ($statement->seatedOwner !== null && $incumbent instanceof User) {
                    $this->applyOwnershipSubject($incumbent, $statement->seatedOwner);
                }

                if ($incoming instanceof User) {
                    $this->applyOwnershipSubject($incoming, $statement->owner);
                }

                DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
                    'managed_ownership_generation' => $connection->authorityGeneration,
                    'managed_ownership_roster_version' => $statement->rosterVersion,
                    'managed_ownership_response_sequence' => $statement->responseSequence,
                    'updated_at' => CarbonImmutable::now(),
                ]);

                return in_array($disposition, ['acquisition', 'reaffirmation', 'transfer'], true);
            });
        } catch (QueryException $exception) {
            $this->refuseOwnerSlotViolation($exception, null, $statement->owner->scalpelsId);

            throw $exception;
        }
    }

    private function applyOwnershipSubject(User $user, ManagedOwnershipSubject $subject): void
    {
        $active = $subject->membershipStatus === 'active';
        $user->forceFill([
            'role' => $subject->role,
            'status' => $active ? 'active' : 'inactive',
            'managed_membership_status' => $subject->membershipStatus,
            'managed_membership_role' => $subject->role,
            'deactivated_at' => $active ? null : CarbonImmutable::now(),
        ])->save();

        if (! $active) {
            StandaloneAccess::invalidateAccountBoundState($user);
        }
    }

    private function incumbentMatches(
        mixed $incumbent,
        ManagedAuthConnection $connection,
        ?string $expectedScalpelsId,
    ): bool {
        if ($expectedScalpelsId === null) {
            return ! ($incumbent instanceof User);
        }

        return $incumbent instanceof User
            && $incumbent->scalpels_issuer === $connection->issuer
            && $incumbent->scalpels_connection_id === $connection->connectionId
            && $incumbent->scalpels_id === $expectedScalpelsId;
    }

    private function ownershipStatementDisposition(ManagedOwnershipStatement $statement): string
    {
        $this->assertOwnershipSubject($statement->owner);

        if ($statement->seatedOwner !== null) {
            $this->assertOwnershipSubject($statement->seatedOwner);
        }

        if ($statement->owner->role !== UserRole::Owner->value
            || $statement->owner->membershipStatus !== 'active') {
            throw new ManagedAuthRefused;
        }

        if ($statement->requestedSeatedOwnerScalpelsId === null) {
            if ($statement->seatedOwner !== null) {
                throw new ManagedAuthRefused;
            }

            return 'acquisition';
        }

        if ($statement->seatedOwner === null
            || $statement->seatedOwner->scalpelsId !== $statement->requestedSeatedOwnerScalpelsId) {
            throw new ManagedAuthRefused;
        }

        if ($statement->owner->scalpelsId === $statement->seatedOwner->scalpelsId) {
            if ($statement->owner != $statement->seatedOwner) {
                throw new ManagedAuthRefused;
            }

            return 'reaffirmation';
        }

        if ($statement->seatedOwner->role === UserRole::Owner->value) {
            throw new ManagedAuthRefused;
        }

        return 'transfer';
    }

    private function assertOwnershipSubject(ManagedOwnershipSubject $subject): void
    {
        if ($subject->scalpelsId === ''
            || strlen($subject->scalpelsId) > 255
            || UserRole::tryFrom($subject->role) === null
            || ! in_array($subject->membershipStatus, ['active', 'removed', 'disabled'], true)) {
            throw new ManagedAuthRefused;
        }
    }

    public function recordFailedAttempt(ManagedAuthConnection $connection, User $subject): void
    {
        $this->transaction(function () use ($connection, $subject): void {
            $this->lockedAuthority($connection);
            $user = User::query()->lockForUpdate()->find($subject->getKey());

            if (! ($user instanceof User)
                || $user->scalpels_issuer !== $connection->issuer
                || $user->scalpels_connection_id !== $connection->connectionId
                || $user->scalpels_id !== $subject->scalpels_id) {
                throw new ManagedAuthRefused;
            }

            $user->forceFill(['membership_checked_at' => CarbonImmutable::now()])->save();
        });
    }

    /**
     * @template T
     *
     * @param  Closure(): T  $callback
     * @return T
     */
    private function transaction(Closure $callback): mixed
    {
        for ($attempt = 1; $attempt <= 3; $attempt++) {
            try {
                return DB::transaction($callback);
            } catch (QueryException $exception) {
                if ($attempt === 3 || ($exception->errorInfo[0] ?? null) !== '40P01') {
                    throw $exception;
                }
            }
        }

        throw new \LogicException('Unreachable transaction retry state.');
    }

    /** @return object{managed_connection_status: mixed, managed_connection_generation: mixed, managed_connection_roster_version: mixed, managed_connection_response_sequence: mixed, managed_ownership_generation: mixed, managed_ownership_roster_version: mixed, managed_ownership_response_sequence: mixed} */
    private function lockedAuthority(ManagedAuthConnection $connection): object
    {
        return $this->authority($connection, true);
    }

    /** @return object{managed_connection_status: mixed, managed_connection_generation: mixed, managed_connection_roster_version: mixed, managed_connection_response_sequence: mixed, managed_ownership_generation: mixed, managed_ownership_roster_version: mixed, managed_ownership_response_sequence: mixed} */
    private function authority(ManagedAuthConnection $connection, bool $lock): object
    {
        $query = DB::table('bfc_authority')->where('key', InstallationAuthority::KEY);

        if ($lock) {
            $query->lockForUpdate();
        }

        $authority = $query->first();

        if (! is_object($authority)
            || $authority->mode !== AuthorityMode::Managed->value
            || $authority->generation !== $connection->authorityGeneration
            || $authority->issuer !== $connection->issuer
            || $authority->connection_id !== $connection->connectionId
            || $authority->organization_id !== $connection->organizationId
            || $authority->installation_id !== $connection->installationId) {
            throw new ManagedAuthRefused;
        }

        return $authority;
    }

    private function connectionAccepted(
        object $authority,
        ManagedAuthConnection $connection,
        ManagedAuthConfirmation|ManagedAuthExchange $response,
    ): bool {
        return $this->newer(
            $this->nullableInt($authority->managed_connection_generation ?? null),
            $this->nullableInt($authority->managed_connection_roster_version ?? null),
            $this->nullableInt($authority->managed_connection_response_sequence ?? null),
            $connection->authorityGeneration,
            $response->rosterVersion,
            $response->responseSequence,
        );
    }

    private function connectionStatus(
        object $authority,
        ManagedAuthConfirmation|ManagedAuthExchange $response,
        bool $connectionAccepted,
    ): string {
        return $connectionAccepted
            ? $response->connectionStatus
            : (is_string($authority->managed_connection_status ?? null)
                ? $authority->managed_connection_status
                : 'active');
    }

    private function storeConnectionDimension(
        ManagedAuthConfirmation|ManagedAuthExchange $response,
        ManagedAuthConnection $connection,
    ): void {
        DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
            'managed_connection_status' => $response->connectionStatus,
            'managed_connection_generation' => $connection->authorityGeneration,
            'managed_connection_roster_version' => $response->rosterVersion,
            'managed_connection_response_sequence' => $response->responseSequence,
            'updated_at' => CarbonImmutable::now(),
        ]);
    }

    private function fillMembershipDimension(
        User $user,
        ManagedAuthConfirmation|ManagedAuthExchange $response,
        ManagedAuthConnection $connection,
        CarbonImmutable $receipt,
    ): void {
        $active = $response->membershipStatus === 'active';
        // managed-auth-v1 requires role on every response, and the authority sends a mandated filler on denials.
        // Only active membership answers write it; see the P3-AC4 errata (2026-09-11) in unified-auth-build-plan.md.
        $roleDimension = $active ? [
            'role' => $response->role,
            'managed_membership_role' => $response->role,
        ] : [];
        $user->forceFill([
            ...$roleDimension,
            'status' => $active ? 'active' : 'inactive',
            'deactivated_at' => $active ? null : $receipt,
            'managed_membership_status' => $response->membershipStatus,
            'managed_membership_generation' => $connection->authorityGeneration,
            'managed_membership_roster_version' => $response->rosterVersion,
            'managed_membership_response_sequence' => $response->responseSequence,
            'managed_membership_responded_at' => $response->respondedAt->format(DATE_RFC3339_EXTENDED),
        ]);
    }

    private function applyDenial(
        ManagedAuthConnection $connection,
        ?User $subject,
        bool $membershipDenied,
        bool $connectionDenied,
    ): void {
        if ($connectionDenied) {
            $subjects = User::query()
                ->where('scalpels_issuer', $connection->issuer)
                ->where('scalpels_connection_id', $connection->connectionId)
                ->lockForUpdate()
                ->get();

            foreach ($subjects as $user) {
                StandaloneAccess::invalidateAccountBoundState($user);
            }

            return;
        }

        if ($membershipDenied && $subject instanceof User) {
            StandaloneAccess::invalidateAccountBoundState($subject);
        }
    }

    private function assertRecognizedRole(string $role): void
    {
        if (UserRole::tryFrom($role) === null) {
            throw new ManagedAuthRefused('managed_role_refused');
        }
    }

    private function ownershipOutcome(
        ?User $subject,
        ManagedAuthConfirmation|ManagedAuthExchange $response,
        bool $membershipAccepted,
        bool $mayPullOwnership,
    ): ?ManagedOwnershipOutcome {
        if (! $membershipAccepted) {
            return null;
        }

        $owner = User::query()->whereNotNull('owner_slot')->lockForUpdate()->first();
        $heldBySubject = $owner instanceof User
            && $subject instanceof User
            && $owner->getKey() === $subject->getKey();
        $active = $response->membershipStatus === 'active';

        if (! $active) {
            if (! $subject instanceof User) {
                return ManagedOwnershipOutcome::OwnershipAbsentDenial;
            }

            return $heldBySubject
                ? ManagedOwnershipOutcome::OwnerDenied
                : ManagedOwnershipOutcome::OwnershipNeutralDenial;
        }

        if ($response->role === UserRole::Owner->value) {
            if (! $owner instanceof User) {
                return ManagedOwnershipOutcome::OwnerAcquire;
            }

            if ($heldBySubject) {
                return ManagedOwnershipOutcome::OwnerReaffirm;
            }

            $this->refuseOwnerTransition($subject, $response, $mayPullOwnership);
        }

        if (! $heldBySubject) {
            return ManagedOwnershipOutcome::OwnershipNeutral;
        }

        $this->refuseOwnerTransition($subject, $response, false);
    }

    private function refuseOwnerTransition(
        ?User $subject,
        ManagedAuthConfirmation|ManagedAuthExchange $response,
        bool $pullOwnership,
    ): never {

        try {
            Log::warning('Built for Cloud refused a managed response that would change the Owner.', [
                'reason_code' => 'managed_owner_transition_refused',
                'user_id' => $subject?->getKey(),
                'scalpels_id' => $response->scalpelsId,
            ]);
        } catch (Throwable) {
            // The typed refusal below remains observable even if the logger is unavailable.
        }

        if ($pullOwnership
            && $response instanceof ManagedAuthExchange
            && $response->membershipStatus === 'active'
            && $response->role === UserRole::Owner->value) {
            throw new ManagedOwnerContested;
        }

        throw new ManagedAuthRefused('managed_owner_transition_refused');
    }

    private function seatedOwnerScalpelsId(): ?string
    {
        $value = User::query()->whereNotNull('owner_slot')->value('scalpels_id');

        return is_string($value) && $value !== '' ? $value : null;
    }

    private function refuseOwnerSlotViolation(
        Throwable $exception,
        mixed $userId,
        string $scalpelsId,
    ): void {
        if (! $this->violatedOwnerSlot($exception)) {
            return;
        }

        try {
            Log::warning('Built for Cloud refused a concurrent managed Owner acquisition.', [
                'reason_code' => 'managed_owner_transition_refused',
                'user_id' => $userId,
                'scalpels_id' => $scalpelsId,
            ]);
        } catch (Throwable) {
            // The typed refusal below remains observable even if the logger is unavailable.
        }

        throw new ManagedAuthRefused('managed_owner_transition_refused', previous: $exception);
    }

    private function violatedOwnerSlot(Throwable $exception): bool
    {
        for ($current = $exception; $current !== null; $current = $current->getPrevious()) {
            if (! $current instanceof QueryException) {
                continue;
            }

            if ($current instanceof UniqueConstraintViolationException
                && ($current->index === 'users_owner_slot_unique'
                    || $current->columns === ['owner_slot'])) {
                return true;
            }
        }

        return false;
    }

    private function newer(
        ?int $storedGeneration,
        ?int $storedRosterVersion,
        ?int $storedResponseSequence,
        int $generation,
        int $rosterVersion,
        int $responseSequence,
    ): bool {
        if ($storedGeneration === null) {
            return true;
        }

        if ($storedRosterVersion === null || $storedResponseSequence === null) {
            return true;
        }

        if ($generation !== $storedGeneration) {
            return $generation > $storedGeneration;
        }

        return $rosterVersion >= $storedRosterVersion
            && $responseSequence > $storedResponseSequence;
    }

    private function nullableInt(mixed $value): ?int
    {
        return is_int($value) ? $value : null;
    }
}
