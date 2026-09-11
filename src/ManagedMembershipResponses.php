<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Exceptions\ManagedAuthRefused;
use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Throwable;

final class ManagedMembershipResponses
{
    public function __construct(private readonly ManagedIdentityUpsert $identities) {}

    public function applyConfirmation(
        ManagedAuthConnection $connection,
        User $subject,
        ManagedAuthConfirmation $response,
    ): bool {
        return DB::transaction(function () use ($connection, $subject, $response): bool {
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
            $connectionAccepted = $this->newer(
                $this->nullableInt($authority->managed_connection_generation),
                $this->nullableInt($authority->managed_connection_roster_version),
                $this->nullableInt($authority->managed_connection_response_sequence),
                $connection->authorityGeneration,
                $response->rosterVersion,
                $response->responseSequence,
            );

            $this->assertRecognizedRole($response->role);
            $this->refuseOwnerTransition($user, $response, $membershipAccepted);

            if ($connectionAccepted) {
                $this->storeConnectionDimension($response, $connection);
            }

            if ($membershipAccepted) {
                $this->fillMembershipDimension($user, $response, $connection, $receipt);
            }

            $active = ($membershipAccepted
                ? $response->membershipStatus
                : $user->managed_membership_status) === 'active'
                && ($connectionAccepted
                    ? $response->connectionStatus
                    : ($authority->managed_connection_status ?? 'active')) === 'active';
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
    }

    public function applyExchange(
        ManagedAuthConnection $connection,
        ManagedAuthExchange $response,
    ): ?User {
        if (! $response->contactEmailVerified) {
            return null;
        }

        return DB::transaction(function () use ($connection, $response): ?User {
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
            $connectionAccepted = $this->newer(
                $this->nullableInt($authority->managed_connection_generation),
                $this->nullableInt($authority->managed_connection_roster_version),
                $this->nullableInt($authority->managed_connection_response_sequence),
                $connection->authorityGeneration,
                $response->rosterVersion,
                $response->responseSequence,
            );

            $this->assertRecognizedRole($response->role);
            $this->refuseOwnerTransition($user, $response, $membershipAccepted);
            $receipt = CarbonImmutable::now();

            if ($connectionAccepted) {
                $this->storeConnectionDimension($response, $connection);
            }

            $active = ($membershipAccepted
                ? $response->membershipStatus
                : $user?->managed_membership_status) === 'active'
                && ($connectionAccepted
                    ? $response->connectionStatus
                    : ($authority->managed_connection_status ?? 'active')) === 'active';

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

    public function recordFailedAttempt(ManagedAuthConnection $connection, User $subject): void
    {
        DB::transaction(function () use ($connection, $subject): void {
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

    /** @return object{managed_connection_status: mixed, managed_connection_generation: mixed, managed_connection_roster_version: mixed, managed_connection_response_sequence: mixed} */
    private function lockedAuthority(ManagedAuthConnection $connection): object
    {
        $authority = DB::table('bfc_authority')
            ->where('key', InstallationAuthority::KEY)
            ->lockForUpdate()
            ->first();

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

    private function refuseOwnerTransition(
        ?User $subject,
        ManagedAuthConfirmation|ManagedAuthExchange $response,
        bool $membershipAccepted,
    ): void {
        if (! $membershipAccepted) {
            return;
        }

        $existingOwner = $subject?->role === 'owner';
        $createsOwner = ! $existingOwner
            && $response->role === 'owner';
        $removesOwner = $existingOwner
            && ($response->membershipStatus !== 'active' || $response->role !== 'owner');

        if (! $createsOwner && ! $removesOwner) {
            return;
        }

        try {
            Log::warning('Built for Cloud refused a managed response that would change the Owner.', [
                'reason_code' => 'managed_owner_transition_refused',
                'user_id' => $subject?->getKey(),
                'scalpels_id' => $response->scalpelsId,
            ]);
        } catch (Throwable) {
            // The typed refusal below remains observable even if the logger is unavailable.
        }

        throw new ManagedAuthRefused('managed_owner_transition_refused');
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
