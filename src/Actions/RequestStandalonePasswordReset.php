<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Actions;

use ArtisanBuild\BuiltForCloud\Notifications\StandalonePasswordResetNotification;
use ArtisanBuild\BuiltForCloud\StandaloneAccess;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Notification;
use Throwable;

final class RequestStandalonePasswordReset
{
    public function __invoke(string $candidate): void
    {
        $email = StandaloneAccess::normalizeEmail($candidate);
        $user = filter_var($email, FILTER_VALIDATE_EMAIL) !== false
            ? User::query()->whereRaw('lower(email) = ?', [$email])->first()
            : null;

        if (! $user instanceof User || ! StandaloneAccess::userCanReceiveRecovery($user)) {
            return;
        }

        $token = bin2hex(random_bytes(32));
        DB::transaction(function () use ($user, $token): void {
            DB::table('password_reset_tokens')->updateOrInsert(
                ['email' => $user->email],
                ['token' => hash('sha256', $token), 'created_at' => now()],
            );
        });

        try {
            Notification::route('mail', $user->email)
                ->notify(new StandalonePasswordResetNotification($token, $user->email));
        } catch (Throwable $exception) {
            Log::warning('Built for Cloud could not deliver a password reset notification.', [
                'exception' => $exception::class,
            ]);
        }
    }
}
