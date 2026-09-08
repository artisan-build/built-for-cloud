<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Actions;

use ArtisanBuild\BuiltForCloud\HumanInvitationResult;
use ArtisanBuild\BuiltForCloud\Invitation;
use ArtisanBuild\BuiltForCloud\MintedSecret;
use ArtisanBuild\BuiltForCloud\Notifications\HumanInvitationNotification;
use ArtisanBuild\BuiltForCloud\RolePolicy;
use ArtisanBuild\BuiltForCloud\StandaloneAccess;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Str;
use RuntimeException;
use Throwable;

final class IssueHumanInvitation
{
    public function __invoke(User $actor, string $email, UserRole $role): HumanInvitationResult
    {
        if ($role === UserRole::Owner) {
            throw new RuntimeException('Owner invitations are not available.');
        }

        $email = StandaloneAccess::normalizeEmail($email);
        $ttl = max(Invitation::TTL_MIN_SECONDS, min(
            Invitation::TTL_MAX_SECONDS,
            (int) config('built-for-cloud.standalone.invitation_ttl_seconds', 259200),
        ));

        $result = DB::transaction(function () use ($actor, $email, $role, $ttl): HumanInvitationResult {
            $lockedActor = User::query()->lockForUpdate()->find($actor->getKey());

            if (! $lockedActor instanceof User
                || $lockedActor->status !== 'active'
                || ! RolePolicy::canManage($lockedActor->role, $role)) {
                abort(403);
            }

            Invitation::query()
                ->where('email', $email)
                ->whereNull('accepted_at')
                ->whereNull('cancelled_at')
                ->where('expires_at', '<=', now())
                ->update(['cancelled_at' => now()]);

            if (User::query()->whereRaw('lower(email) = ?', [$email])->exists()
                || Invitation::query()->where('pending_email', $email)->exists()) {
                abort(422, 'That email cannot be invited.');
            }

            do {
                $token = new MintedSecret(bin2hex(random_bytes(32)));
            } while (Invitation::query()->where('token', $token->hash())->exists());

            $invitation = Invitation::query()->create([
                'id' => (string) Str::uuid(),
                'email' => $email,
                'token' => $token->hash(),
                'invited_by' => (string) $lockedActor->getKey(),
                'role' => $role->value,
                'expires_at' => now()->addSeconds($ttl),
            ]);

            return new HumanInvitationResult($invitation, $token);
        });

        try {
            Notification::route('mail', $result->invitation->email)
                ->notify(new HumanInvitationNotification(
                    (string) $result->invitation->getKey(),
                    $result->token->reveal(),
                    $result->invitation->email,
                ));
        } catch (Throwable $exception) {
            Invitation::query()
                ->whereKey($result->invitation->getKey())
                ->whereNull('accepted_at')
                ->update(['cancelled_at' => now()]);
            Log::warning('Built for Cloud could not deliver an invitation notification.', [
                'exception' => $exception::class,
            ]);

            throw new RuntimeException('Invitation delivery failed.');
        }

        return $result;
    }
}
