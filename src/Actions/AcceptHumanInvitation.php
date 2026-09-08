<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Actions;

use ArtisanBuild\BuiltForCloud\AuditActor;
use ArtisanBuild\BuiltForCloud\Invitation;
use ArtisanBuild\BuiltForCloud\LifecycleEventRecorder;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use RuntimeException;
use SensitiveParameter;

final readonly class AcceptHumanInvitation
{
    public function __construct(private LifecycleEventRecorder $recorder) {}

    public function __invoke(#[SensitiveParameter] string $token, string $name, string $password): User
    {
        return DB::transaction(function () use ($token, $name, $password): User {
            $invitation = Invitation::query()
                ->where('token', Invitation::hashToken($token))
                ->lockForUpdate()
                ->first();

            $role = $invitation instanceof Invitation ? UserRole::tryFrom((string) $invitation->role) : null;

            if (! $invitation instanceof Invitation
                || $invitation->email === null
                || ! in_array($role, [UserRole::Admin, UserRole::Member], true)
                || $invitation->accepted_at !== null
                || $invitation->cancelled_at !== null
                || $invitation->expires_at === null
                || $invitation->expires_at->lessThanOrEqualTo(now())
                || User::query()->whereRaw('lower(email) = ?', [$invitation->email])->exists()) {
                throw new RuntimeException('This invitation is not available.');
            }

            $user = new User([
                'name' => $name,
                'email' => $invitation->email,
                'password' => Hash::make($password),
            ]);
            $user->forceFill([
                'role' => $role->value,
                'status' => 'active',
                'email_verified_at' => now(),
                'original_contact_email' => $invitation->email,
                'email_is_generated' => false,
            ])->save();

            $burned = Invitation::query()
                ->whereKey($invitation->getKey())
                ->whereNull('accepted_at')
                ->whereNull('cancelled_at')
                ->update([
                    'accepted_at' => now(),
                    'used_by' => (string) $user->getKey(),
                ]);

            if ($burned !== 1) {
                throw new RuntimeException('This invitation is not available.');
            }

            $this->recorder->record(
                event: LifecycleEventType::Exchanged,
                codeId: (string) $invitation->getKey(),
                actor: AuditActor::credentialHolder((string) $invitation->getKey()),
                recipient: $invitation->email,
            );

            $user->refresh();

            return $user;
        }, 3);
    }
}
