<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\Console\ActingPrincipalResolver;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\LandingManifest;
use ArtisanBuild\BuiltForCloud\ManagedTransitionDirection;
use ArtisanBuild\BuiltForCloud\RolePolicy;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Contracts\View\View;

final readonly class UiHome
{
    public function __invoke(ActingPrincipalResolver $principals, ?LandingManifest $manifest): View
    {
        /** @var User $user */
        $user = $principals->resolve()->principal;
        $authority = InstallationAuthority::current();
        $role = RolePolicy::role($user->role);

        $memberManagement = (bool) config('built-for-cloud.ui.member_management', false)
            && RolePolicy::canManageMembers($role);
        $managedMemberManagement = $memberManagement && $authority->mode === AuthorityMode::Managed;

        return view('bfc::home', [
            'manifest' => $manifest,
            'memberManagement' => $memberManagement,
            'memberManagementHref' => $managedMemberManagement
                ? '#managed-members'
                : route('bfc.members.index'),
            'managedMembers' => $managedMemberManagement
                ? User::query()->whereNotNull('scalpels_id')->orderBy('name')->orderBy('id')->get()
                : collect(),
            'managedMemberManagement' => $managedMemberManagement,
            'sessionManagement' => (bool) config('built-for-cloud.ui.session_management', false)
                && $authority->mode === AuthorityMode::Standalone,
            'managedTransitions' => (bool) config('built-for-cloud.ui.managed_transitions', false)
                && $role === UserRole::Owner,
            'personalCredentials' => (bool) config('built-for-cloud.ui.personal_credentials', false),
            'installationCredentials' => (bool) config('built-for-cloud.ui.installation_credentials', false),
            'transitionDirection' => $authority->mode === AuthorityMode::Standalone
                ? ManagedTransitionDirection::Adopt
                : ManagedTransitionDirection::Exit,
        ]);
    }
}
