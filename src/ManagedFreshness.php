<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Exceptions\ManagedAuthRefused;
use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

final class ManagedFreshness
{
    private const int FRESH_SECONDS = 300;

    private const int GRACE_SECONDS = 1800;

    private const int LOCK_SECONDS = 10;

    private const int MINIMUM_RETRY_SECONDS = 30;

    private const int MAXIMUM_RETRY_SECONDS = 300;

    public function __construct(
        private readonly ManagedAuthClient $client,
        private readonly ManagedMembershipResponses $responses,
    ) {}

    public function allows(User $subject): bool
    {
        $connection = ManagedAuthConnection::current();
        $this->assertSubjectBinding($connection, $subject);
        $subject->refresh();

        if ($this->storedAllows($subject) && $this->age($subject) < self::FRESH_SECONDS) {
            return true;
        }

        $key = hash('sha256', implode("\0", [
            $connection->issuer,
            $connection->connectionId,
            (string) $subject->scalpels_id,
        ]));
        $lock = Cache::lock('bfc:managed-refresh:'.$key, self::LOCK_SECONDS);

        if (! $lock->get()) {
            return $this->storedAllows($subject->refresh());
        }

        try {
            $subject->refresh();

            if ($this->storedAllows($subject) && $this->age($subject) < self::FRESH_SECONDS) {
                return true;
            }

            $attemptKey = 'bfc:managed-refresh-attempt:'.$key;
            $now = CarbonImmutable::now();
            $nextAttemptAt = Cache::get($attemptKey);

            if (is_int($nextAttemptAt) && $now->getTimestamp() < $nextAttemptAt) {
                return $this->storedAllows($subject);
            }

            // Charge the slot before any bytes leave this process.
            Cache::put(
                $attemptKey,
                $now->getTimestamp() + self::MINIMUM_RETRY_SECONDS,
                self::MAXIMUM_RETRY_SECONDS,
            );

            try {
                $confirmation = $this->client->confirm($connection, $subject);

                return $this->responses->applyConfirmation($connection, $subject, $confirmation);
            } catch (ManagedAuthRefused $exception) {
                if ($exception->recordsFailedAttempt) {
                    $this->responses->recordFailedAttempt($connection, $subject);
                }
                $retryAfter = min(
                    self::MAXIMUM_RETRY_SECONDS,
                    max(self::MINIMUM_RETRY_SECONDS, $exception->retryAfterSeconds ?? 0),
                );
                Cache::put(
                    $attemptKey,
                    CarbonImmutable::now()->getTimestamp() + $retryAfter,
                    self::MAXIMUM_RETRY_SECONDS,
                );

                return $this->storedAllows($subject->refresh());
            }
        } finally {
            $lock->release();
        }
    }

    private function assertSubjectBinding(ManagedAuthConnection $connection, User $subject): void
    {
        if ($subject->scalpels_issuer !== $connection->issuer
            || $subject->scalpels_connection_id !== $connection->connectionId
            || ! is_string($subject->scalpels_id)
            || $subject->scalpels_id === '') {
            throw new ManagedAuthRefused;
        }
    }

    private function storedAllows(User $subject): bool
    {
        if (in_array($subject->managed_membership_status, ['removed', 'disabled'], true)) {
            return false;
        }

        $connectionStatus = DB::table('bfc_authority')
            ->where('key', InstallationAuthority::KEY)
            ->value('managed_connection_status');

        return $connectionStatus !== 'inactive' && $this->age($subject) < self::GRACE_SECONDS;
    }

    private function age(User $subject): int
    {
        if ($subject->membership_confirmed_at === null) {
            return PHP_INT_MAX;
        }

        $age = CarbonImmutable::now()->getTimestamp() - $subject->membership_confirmed_at->getTimestamp();

        return $age < 0 ? PHP_INT_MAX : $age;
    }
}
