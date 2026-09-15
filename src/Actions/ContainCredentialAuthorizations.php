<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Actions;

use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationDenialReason;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationOwnership;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationStatus;
use ArtisanBuild\BuiltForCloud\CredentialAuthorizationTransitions;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use LogicException;

final readonly class ContainCredentialAuthorizations
{
    public function __construct(private CredentialAuthorizationTransitions $transitions) {}

    public function user(string $userId, ?AuditActor $actor = null): int
    {
        return $this->contain(
            static fn (Builder $query): Builder => $query
                ->where('ownership', CredentialAuthorizationOwnership::Personal->value)
                ->where('initiating_user_id', $userId),
            CredentialAuthorizationDenialReason::UserRemoved,
            $actor,
        );
    }

    public function subject(Subject $subject, ?AuditActor $actor = null): int
    {
        return $this->contain(
            static fn (Builder $query): Builder => $query
                ->where('subject_type', $subject->type->value)
                ->where('subject_ref', $subject->ref),
            $subject->type === SubjectType::Installation
                ? CredentialAuthorizationDenialReason::InstallationRemoved
                : CredentialAuthorizationDenialReason::SubjectOffboarded,
            $actor,
        );
    }

    public function connection(?AuditActor $actor = null): int
    {
        return $this->contain(
            static fn (Builder $query): Builder => $query,
            CredentialAuthorizationDenialReason::ConnectionInactive,
            $actor,
        );
    }

    /** @param callable(Builder): Builder $scope */
    private function contain(callable $scope, CredentialAuthorizationDenialReason $reason, ?AuditActor $actor): int
    {
        if (DB::transactionLevel() === 0) {
            throw new LogicException('Authorization containment must share its caller transaction.');
        }

        $query = DB::table('credential_authorizations')
            ->whereIn('status', [CredentialAuthorizationStatus::Pending->value, CredentialAuthorizationStatus::Approved->value]);
        $rows = $scope($query)->orderBy('id')->lockForUpdate()->get();
        $contained = 0;

        foreach ($rows as $authorization) {
            $contained += $this->transitions->deny($authorization, $reason, $actor) ? 1 : 0;
        }

        return $contained;
    }
}
