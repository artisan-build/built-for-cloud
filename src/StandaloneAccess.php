<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

use Illuminate\Database\ConnectionInterface;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Schema;
use RuntimeException;

final class StandaloneAccess
{
    public const string SESSION_VERSION_KEY = 'bfc.auth_session_version';

    public static function normalizeEmail(string $email): string
    {
        return strtolower(trim($email));
    }

    public static function userCanAuthenticate(User $user): bool
    {
        return $user->status === 'active'
            && $user->roleValue() !== null
            && is_string($user->password)
            && $user->password !== '';
    }

    public static function userCanReceiveRecovery(User $user): bool
    {
        return $user->status === 'active'
            && $user->roleValue() !== null
            && $user->hasVerifiedEmail()
            && ! $user->email_is_generated
            && filter_var($user->email, FILTER_VALIDATE_EMAIL) !== false;
    }

    public static function passwordMatches(User $user, string $password): bool
    {
        if (! self::userCanAuthenticate($user)) {
            return false;
        }

        try {
            return Hash::check($password, (string) $user->password);
        } catch (RuntimeException) {
            return false;
        }
    }

    public static function sessionStore(): ?ConnectionInterface
    {
        if (config('session.driver') !== 'database') {
            return null;
        }

        $connection = config('session.connection');
        $database = DB::connection(is_string($connection) && $connection !== '' ? $connection : null);
        $table = (string) config('session.table', 'sessions');

        return Schema::connection($database->getName())->hasTable($table) ? $database : null;
    }

    public static function invalidateSessions(User $user): int
    {
        $user->forceFill(['auth_session_version' => $user->auth_session_version + 1])->save();
        $table = (string) config('session.table', 'sessions');
        $deleted = Schema::hasTable($table)
            ? DB::table($table)->where('user_id', (string) $user->getKey())->delete()
            : 0;
        $database = self::sessionStore();
        $sessionConnection = config('session.connection');

        if ($database === null
            || $sessionConnection === null
            || $sessionConnection === config('database.default')) {
            return $deleted;
        }

        return $deleted + $database->table($table)
            ->where('user_id', (string) $user->getKey())
            ->delete();
    }

    public static function invalidateAccountBoundState(User $user): void
    {
        self::invalidateSessions($user);

        DB::table('password_reset_tokens')->where('email', $user->email)->delete();

        Invitation::query()
            ->whereNull('accepted_at')
            ->whereNull('cancelled_at')
            ->where(function ($query) use ($user): void {
                $query->where('email', $user->email)
                    ->orWhere('invited_by', (string) $user->getKey());
            })
            ->update(['cancelled_at' => now()]);

        Credential::query()
            ->where('user_id', (string) $user->getKey())
            ->whereNull('revoked_at')
            ->update(['revoked_at' => now()]);
    }
}
