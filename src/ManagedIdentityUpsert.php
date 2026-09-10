<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use ArtisanBuild\BuiltForCloud\Exceptions\ManagedAuthRefused;
use Carbon\CarbonImmutable;
use Illuminate\Database\QueryException;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;

final class ManagedIdentityUpsert
{
    private const int MAX_INSERT_ATTEMPTS = 1000;

    /**
     * The caller must already have refused non-active membership, a non-active connection, and an
     * unverified contact. Otherwise this method writes an active row, applies the supplied role,
     * and advances `membership_confirmed_at`, allowing a denied subject to be served from stored
     * state for 300 seconds with no authority call.
     *
     * @internal For the managed authentication callback only.
     */
    public function upsert(ManagedAuthConnection $connection, ManagedAuthExchange $exchange): User
    {
        if (strlen($exchange->displayName) > 255
            || ! $this->validEmail($exchange->contactEmail)) {
            throw new ManagedAuthRefused;
        }

        $candidateNumber = 0;

        for ($attempt = 0; $attempt < self::MAX_INSERT_ATTEMPTS; $attempt++) {
            try {
                return DB::transaction(function () use ($connection, $exchange, $candidateNumber): User {
                    $user = User::query()
                        ->where('scalpels_issuer', $connection->issuer)
                        ->where('scalpels_connection_id', $connection->connectionId)
                        ->where('scalpels_id', $exchange->scalpelsId)
                        ->lockForUpdate()
                        ->first();

                    if ($user instanceof User) {
                        return $this->update($user, $exchange);
                    }

                    return $this->insert($connection, $exchange, $candidateNumber);
                });
            } catch (QueryException $exception) {
                if ($this->violatedExternalIdentity($exception)) {
                    continue;
                }

                if ($this->violatedEmail($exception)) {
                    $candidateNumber++;

                    continue;
                }

                if ($exception instanceof UniqueConstraintViolationException
                    || $this->isIntegrityConstraintViolation($exception)) {
                    throw new ManagedAuthRefused(previous: $exception);
                }

                throw $exception;
            }
        }

        throw new ManagedAuthRefused;
    }

    private function update(User $user, ManagedAuthExchange $exchange): User
    {
        $now = CarbonImmutable::now();
        $bestEffortConflict = User::query()
            ->where($user->getKeyName(), '!=', $user->getKey())
            ->where('normalized_email', strtolower($exchange->contactEmail))
            ->exists();

        $user->forceFill([
            'role' => $exchange->role,
            'status' => 'active',
            'deactivated_at' => null,
            'name' => $exchange->displayName,
            'original_contact_email' => $exchange->contactEmail,
            'membership_confirmed_at' => $now,
            'membership_checked_at' => $now,
            'membership_response_at' => $now,
            'email_conflict_at' => $bestEffortConflict ? $now : null,
            'email_conflict_source' => $bestEffortConflict ? $exchange->contactEmail : null,
        ])->save();

        return $user->refresh();
    }

    private function insert(
        ManagedAuthConnection $connection,
        ManagedAuthExchange $exchange,
        int $candidateNumber,
    ): User {
        $now = CarbonImmutable::now();
        $generated = $candidateNumber > 0;
        $user = new User;
        $user->forceFill([
            'name' => $exchange->displayName,
            'email' => $generated
                ? $this->generatedEmail($exchange->contactEmail, $candidateNumber)
                : $exchange->contactEmail,
            'role' => $exchange->role,
            'status' => 'active',
            'deactivated_at' => null,
            'scalpels_issuer' => $connection->issuer,
            'scalpels_connection_id' => $connection->connectionId,
            'scalpels_id' => $exchange->scalpelsId,
            'original_contact_email' => $exchange->contactEmail,
            'email_is_generated' => $generated,
            'membership_confirmed_at' => $now,
            'membership_checked_at' => $now,
            'membership_response_at' => $now,
            'email_conflict_at' => $generated ? $now : null,
            'email_conflict_source' => $generated ? $exchange->contactEmail : null,
        ]);
        $user->save();

        return $user->refresh();
    }

    private function generatedEmail(string $email, int $candidateNumber): string
    {
        $separator = strrpos($email, '@');

        if ($separator === false) {
            throw new ManagedAuthRefused;
        }

        $local = substr($email, 0, $separator);
        $domain = substr($email, $separator + 1);
        $suffix = $candidateNumber === 1 ? '+bfc' : '+bfc-'.$candidateNumber;
        $maximumLocalLength = min(64, 255 - strlen($domain) - 1);
        $prefixLength = $maximumLocalLength - strlen($suffix);

        if ($prefixLength < 1) {
            throw new ManagedAuthRefused;
        }

        if (strlen($local) > $prefixLength && str_contains($local, '+')) {
            throw new ManagedAuthRefused;
        }

        $candidate = substr($local, 0, $prefixLength).$suffix.'@'.$domain;

        if (! $this->validEmail($candidate)) {
            throw new ManagedAuthRefused;
        }

        return $candidate;
    }

    private function validEmail(string $email): bool
    {
        return strlen($email) <= 255 && filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }

    private function violatedExternalIdentity(QueryException $exception): bool
    {
        if (! $exception instanceof UniqueConstraintViolationException) {
            return false;
        }

        return $exception->index === 'users_scalpels_identity_unique'
            || $exception->columns === ['scalpels_issuer', 'scalpels_connection_id', 'scalpels_id'];
    }

    private function violatedEmail(QueryException $exception): bool
    {
        if (! $exception instanceof UniqueConstraintViolationException) {
            return false;
        }

        return in_array($exception->index, [
            'users_normalized_email_unique',
            'users_email_unique',
        ], true) || in_array($exception->columns, [
            ['normalized_email'],
            ['email'],
        ], true);
    }

    private function isIntegrityConstraintViolation(QueryException $exception): bool
    {
        $sqlState = $exception->errorInfo[0] ?? $exception->getCode();

        return str_starts_with((string) $sqlState, '23');
    }
}
