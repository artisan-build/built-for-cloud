<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Exceptions\ManagedAuthRefused;
use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;

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

            if ($connectionAccepted) {
                $this->storeConnectionDimension($response, $connection);
            }

            if ($membershipAccepted) {
                $this->fillMembershipDimension($user, $response, $connection);
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
                if ($user instanceof User) {
                    if ($membershipAccepted) {
                        $this->fillMembershipDimension($user, $response, $connection);
                    }

                    $receipt = CarbonImmutable::now();
                    $user->forceFill([
                        'membership_checked_at' => $receipt,
                        'membership_response_at' => $receipt,
                    ])->save();
                }

                return null;
            }

            if (! $membershipAccepted) {
                return $user;
            }

            $user = $this->identities->upsert($connection, $response);
            $this->fillMembershipDimension($user, $response, $connection);
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
    ): void {
        $user->forceFill([
            'managed_membership_status' => $response->membershipStatus,
            'managed_membership_role' => $response->role,
            'managed_membership_generation' => $connection->authorityGeneration,
            'managed_membership_roster_version' => $response->rosterVersion,
            'managed_membership_response_sequence' => $response->responseSequence,
            'managed_membership_responded_at' => $response->respondedAt->format(DATE_RFC3339_EXTENDED),
        ]);
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
