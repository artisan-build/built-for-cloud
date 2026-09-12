<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\Exceptions\ManagedAuthRefused;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\Invitation;
use ArtisanBuild\BuiltForCloud\ManagedTransition;
use ArtisanBuild\BuiltForCloud\ManagedTransitionDirection;
use ArtisanBuild\BuiltForCloud\ManagedTransitions as TransitionService;
use ArtisanBuild\BuiltForCloud\ManagedTransitionStatus;
use ArtisanBuild\BuiltForCloud\RolePolicy;
use ArtisanBuild\BuiltForCloud\StandaloneAccess;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Contracts\View\View;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;

final class ManageTransitions
{
    public function index(Request $request, string $direction): View
    {
        $this->owner($request);

        return $this->view(ManagedTransitionDirection::from($direction));
    }

    public function store(Request $request, string $direction, TransitionService $transitions): RedirectResponse
    {
        $actor = $this->owner($request);

        try {
            $transition = $transitions->prepare($actor, ManagedTransitionDirection::from($direction));
            $transition = $transitions->fetchRoster($transition);
            $transition = $transitions->proposeDefault($transition);
        } catch (ManagedAuthRefused) {
            throw ValidationException::withMessages(['transition' => 'The transition could not be prepared.']);
        }

        return redirect()->route('bfc.transitions.edit', $transition);
    }

    public function edit(Request $request, string $transition): View
    {
        $this->owner($request);
        $transition = $this->transition($transition);

        if (! in_array($transition->status, [
            ManagedTransitionStatus::Proposed,
            ManagedTransitionStatus::Staging,
            ManagedTransitionStatus::Staged,
            ManagedTransitionStatus::Committed,
            ManagedTransitionStatus::Acknowledging,
        ], true)) {
            abort(409);
        }

        return $this->view($transition->direction, $transition);
    }

    public function update(
        Request $request,
        string $transition,
        TransitionService $transitions,
    ): RedirectResponse {
        $actor = $this->owner($request);
        $transition = $this->transition($transition);

        try {
            $transitions->proposeForOwner($actor, $transition, $this->mapping($request, $transition));
        } catch (ManagedAuthRefused) {
            throw ValidationException::withMessages(['mapping' => 'The complete proposal must use unique final emails and legal dispositions.']);
        }

        return redirect()->route('bfc.transitions.edit', $transition)->with('status', 'proposal-saved');
    }

    public function complete(
        Request $request,
        string $transition,
        TransitionService $transitions,
    ): RedirectResponse {
        $actor = $this->owner($request);
        $transition = $this->transition($transition);

        try {
            $completed = $transitions->complete($actor, $transition);
        } catch (ManagedAuthRefused) {
            if (InstallationAuthority::current()->generation !== $transition->generation_before) {
                StandaloneAccess::endCurrentSession($request, auth()->guard());
            }

            throw ValidationException::withMessages(['transition' => 'The transition could not be completed. Retry the same transition.']);
        }

        StandaloneAccess::endCurrentSession($request, auth()->guard());

        return redirect()->route(
            $completed->direction === ManagedTransitionDirection::Exit ? 'bfc.login' : 'bfc.managed.login',
        );
    }

    private function view(
        ManagedTransitionDirection $direction,
        ?ManagedTransition $transition = null,
    ): View {
        $roster = collect();
        $mappings = collect();
        if ($transition instanceof ManagedTransition) {
            $roster = DB::table('bfc_managed_transition_roster_members')
                ->where('managed_transition_id', $transition->id)
                ->orderBy('ordinal')
                ->get();
            $mappings = DB::table('bfc_managed_transition_mappings')
                ->where('managed_transition_id', $transition->id)
                ->orderBy('ordinal')
                ->get();
        }

        $users = User::query()->orderBy('name')->orderBy('id')->get();
        $invitations = Invitation::query()->pending()->orderBy('created_at')->get();

        return view()->file(__DIR__.'/../../../resources/views/auth/managed-transition.blade.php', [
            'direction' => $direction,
            'transition' => $transition,
            'roster' => $roster,
            'users' => $users,
            'invitations' => $invitations,
            'mappingsBySubject' => $mappings->whereNotNull('scalpels_id')->keyBy('scalpels_id'),
            'mappingsByLocal' => $mappings->whereNotNull('local_id')->keyBy(
                static fn (object $mapping): string => $mapping->local_kind.':'.$mapping->local_id,
            ),
            'affordanceEnabled' => (bool) config('built-for-cloud.ui.managed_transitions', false),
        ]);
    }

    /** @return list<array<string, mixed>> */
    private function mapping(Request $request, ManagedTransition $transition): array
    {
        $localRows = $request->input('locals');
        if (! is_array($localRows)) {
            throw new ManagedAuthRefused;
        }

        return $transition->direction === ManagedTransitionDirection::Adopt
            ? $this->adoptionMapping($request, $transition, $localRows)
            : $this->exitMapping($localRows, $transition);
    }

    /**
     * @param  array<array-key, mixed>  $localRows
     * @return list<array<string, mixed>>
     */
    private function adoptionMapping(Request $request, ManagedTransition $transition, array $localRows): array
    {
        $rosterRows = $request->input('roster');
        if (! is_array($rosterRows)) {
            throw new ManagedAuthRefused;
        }

        $roster = DB::table('bfc_managed_transition_roster_members')
            ->where('managed_transition_id', $transition->id)
            ->get()
            ->keyBy('scalpels_id');
        $mapping = [];
        $linkedLocals = [];

        foreach ($rosterRows as $row) {
            if (! is_array($row) || ! is_string($row['scalpels_id'] ?? null)) {
                throw new ManagedAuthRefused;
            }

            $member = $roster->get($row['scalpels_id']);
            if (! is_object($member)) {
                throw new ManagedAuthRefused;
            }

            $choice = $row['choice'] ?? null;
            if (is_string($choice) && str_starts_with($choice, 'link:')) {
                $local = $this->localReference(substr($choice, 5));
                if ($local === null) {
                    throw new ManagedAuthRefused;
                }
                $linkedLocals[$local['kind'].':'.$local['id']] = true;
                $mapping[] = [
                    'scalpels_id' => $member->scalpels_id,
                    'local_kind' => $local['kind'],
                    'local_id' => $local['id'],
                    'role' => $member->role,
                    'disposition' => 'link',
                    'final_email' => array_key_exists('final_email', $row)
                        ? $this->nullableString($row['final_email'])
                        : $this->localEmail($local['kind'], $local['id']),
                ];

                continue;
            }

            $disposition = $choice;
            if ($disposition === 'create') {
                $mapping[] = [
                    'scalpels_id' => $member->scalpels_id,
                    'local_kind' => null,
                    'local_id' => null,
                    'role' => $member->role,
                    'disposition' => 'create',
                    'final_email' => array_key_exists('final_email', $row)
                        ? $this->nullableString($row['final_email'])
                        : $member->contact_email,
                ];
            } elseif ($disposition === 'defer_to_managed_jit') {
                $mapping[] = [
                    'scalpels_id' => $member->scalpels_id,
                    'local_kind' => null,
                    'local_id' => null,
                    'role' => null,
                    'disposition' => 'defer_to_managed_jit',
                    'final_email' => null,
                ];
            } else {
                throw new ManagedAuthRefused;
            }
        }

        foreach ($localRows as $row) {
            $local = $this->localRow($row);
            if (! isset($linkedLocals[$local['kind'].':'.$local['id']])) {
                $mapping[] = [
                    'scalpels_id' => null,
                    'local_kind' => $local['kind'],
                    'local_id' => $local['id'],
                    'role' => null,
                    'disposition' => 'exclude',
                    'final_email' => null,
                ];
            }
        }

        return $mapping;
    }

    /**
     * @param  array<array-key, mixed>  $localRows
     * @return list<array<string, mixed>>
     */
    private function exitMapping(array $localRows, ManagedTransition $transition): array
    {
        $roster = DB::table('bfc_managed_transition_roster_members')
            ->where('managed_transition_id', $transition->id)
            ->pluck('scalpels_id')
            ->flip();
        $mapping = [];

        foreach ($localRows as $row) {
            $local = $this->localRow($row);
            $choice = is_array($row) ? ($row['choice'] ?? null) : null;
            $subject = is_string($choice) && str_starts_with($choice, 'link:')
                ? $this->nullableString(substr($choice, 5))
                : null;
            if ($subject !== null) {
                if (! $roster->has($subject)) {
                    throw new ManagedAuthRefused;
                }

                $mapping[] = [
                    'scalpels_id' => $subject,
                    'local_kind' => $local['kind'],
                    'local_id' => $local['id'],
                    'role' => array_key_exists('role', $row)
                        ? $this->nullableString($row['role'])
                        : $this->localRole($local['kind'], $local['id']),
                    'disposition' => 'link',
                    'final_email' => array_key_exists('final_email', $row)
                        ? $this->nullableString($row['final_email'])
                        : $this->localEmail($local['kind'], $local['id']),
                ];

                continue;
            }

            $disposition = $choice;
            if ($disposition === 'retain_local' && $local['kind'] === 'user') {
                $mapping[] = [
                    'scalpels_id' => null,
                    'local_kind' => 'user',
                    'local_id' => $local['id'],
                    'role' => array_key_exists('role', $row)
                        ? $this->nullableString($row['role'])
                        : $this->localRole('user', $local['id']),
                    'disposition' => 'retain_local',
                    'final_email' => array_key_exists('final_email', $row)
                        ? $this->nullableString($row['final_email'])
                        : $this->localEmail('user', $local['id']),
                ];
            } elseif ($disposition === 'retain_local' && $local['kind'] === 'invitation') {
                $mapping[] = [
                    'scalpels_id' => null,
                    'local_kind' => 'invitation',
                    'local_id' => $local['id'],
                    'role' => null,
                    'disposition' => 'retain_local',
                    'final_email' => null,
                ];
            } elseif ($disposition === 'exclude') {
                $mapping[] = [
                    'scalpels_id' => null,
                    'local_kind' => $local['kind'],
                    'local_id' => $local['id'],
                    'role' => null,
                    'disposition' => 'exclude',
                    'final_email' => null,
                ];
            } else {
                throw new ManagedAuthRefused;
            }
        }

        return $mapping;
    }

    /** @return array{kind: string, id: string}|null */
    private function localReference(mixed $value): ?array
    {
        $value = $this->nullableString($value);
        if ($value === null) {
            return null;
        }

        $parts = explode(':', $value, 2);
        if (count($parts) !== 2 || ! in_array($parts[0], ['user', 'invitation'], true) || $parts[1] === '') {
            throw new ManagedAuthRefused;
        }

        return ['kind' => $parts[0], 'id' => $parts[1]];
    }

    /** @return array{kind: string, id: string} */
    private function localRow(mixed $row): array
    {
        if (! is_array($row)
            || ! is_string($row['local_kind'] ?? null)
            || ! in_array($row['local_kind'], ['user', 'invitation'], true)
            || ! is_string($row['local_id'] ?? null)
            || $row['local_id'] === '') {
            throw new ManagedAuthRefused;
        }

        return ['kind' => $row['local_kind'], 'id' => $row['local_id']];
    }

    private function localEmail(string $kind, string $id): string
    {
        $email = $kind === 'user'
            ? User::query()->whereKey($id)->value('email')
            : Invitation::query()->pending()->whereKey($id)->value('email');

        if (! is_string($email) || $email === '') {
            throw new ManagedAuthRefused;
        }

        return $email;
    }

    private function localRole(string $kind, string $id): string
    {
        $role = $kind === 'user'
            ? User::query()->whereKey($id)->value('role')
            : Invitation::query()->pending()->whereKey($id)->value('role');

        if (! is_string($role) || $role === '') {
            throw new ManagedAuthRefused;
        }

        return $role;
    }

    private function nullableString(mixed $value): ?string
    {
        return is_string($value) && $value !== '' ? $value : null;
    }

    private function transition(string $id): ManagedTransition
    {
        $transition = ManagedTransition::query()->find($id);
        abort_unless($transition instanceof ManagedTransition, 404);

        return $transition;
    }

    private function owner(Request $request): User
    {
        $actor = $request->user();
        $owner = $actor instanceof User
            ? User::query()->whereKey($actor->getKey())->whereNotNull('owner_slot')->first()
            : null;

        abort_unless($owner instanceof User
            && $owner->status === 'active'
            && RolePolicy::canInitiateModeTransition($owner->role), 403);

        return $owner;
    }
}
