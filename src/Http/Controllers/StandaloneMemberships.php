<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\Actions\IssueHumanInvitation;
use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\Invitation;
use ArtisanBuild\BuiltForCloud\RolePolicy;
use ArtisanBuild\BuiltForCloud\StandaloneAccess;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Contracts\View\View;
use Illuminate\Database\QueryException;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;

final class StandaloneMemberships
{
    public function index(Request $request): View
    {
        $actor = $request->user();

        return view()->file(__DIR__.'/../../../resources/views/auth/members.blade.php', [
            'actor' => $actor,
            'members' => User::query()->orderBy('name')->orderBy('id')->get(),
            'invitations' => Invitation::query()->pending()->orderBy('created_at')->get(),
            'canAdoptManagedAuthority' => RolePolicy::canInitiateModeTransition($actor?->role)
                && InstallationAuthority::current()->mode === AuthorityMode::Standalone,
        ]);
    }

    public function invite(Request $request, IssueHumanInvitation $issue): RedirectResponse
    {
        $input = $request->validate([
            'email' => ['required', 'email', 'max:255'],
            'role' => ['required', 'in:admin,member'],
        ]);
        $actor = $request->user();

        abort_unless($actor instanceof User, 401);
        try {
            $issue($actor, $input['email'], UserRole::from($input['role']));
        } catch (QueryException) {
            throw ValidationException::withMessages(['email' => 'That email cannot be invited.']);
        }

        return back()->with('status', 'invitation-issued');
    }

    public function role(Request $request, string $user): RedirectResponse
    {
        $input = $request->validate(['role' => ['required', 'in:admin,member']]);
        $actor = $request->user();

        abort_unless($actor instanceof User, 401);

        DB::transaction(function () use ($actor, $user, $input): void {
            $lockedActor = User::query()->lockForUpdate()->find($actor->getKey());
            $target = User::query()->lockForUpdate()->find($user);
            $role = UserRole::from($input['role']);

            if (! $lockedActor instanceof User
                || $lockedActor->status !== 'active'
                || $lockedActor->roleValue() !== UserRole::Owner
                || ! $target instanceof User
                || $target->status !== 'active'
                || ! in_array($target->roleValue(), [UserRole::Admin, UserRole::Member], true)) {
                abort(403);
            }

            $target->forceFill(['role' => $role->value])->save();
        }, 3);

        return back()->with('status', 'membership-updated');
    }

    public function deactivate(Request $request, string $user): RedirectResponse
    {
        $actor = $request->user();

        abort_unless($actor instanceof User, 401);

        DB::transaction(function () use ($actor, $user): void {
            $lockedActor = User::query()->lockForUpdate()->find($actor->getKey());
            $target = User::query()->lockForUpdate()->find($user);

            if (! $lockedActor instanceof User
                || $lockedActor->status !== 'active'
                || ! $target instanceof User
                || $target->status !== 'active'
                || ! RolePolicy::canManage($lockedActor->role, $target->role)) {
                abort(403);
            }

            $target->forceFill(['status' => 'inactive', 'deactivated_at' => now()])->save();
            StandaloneAccess::invalidateAccountBoundState($target);
        }, 3);

        return back()->with('status', 'membership-deactivated');
    }
}
