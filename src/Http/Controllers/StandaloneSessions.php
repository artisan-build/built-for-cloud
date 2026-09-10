<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\StandaloneAccess;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Contracts\View\View;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;

final class StandaloneSessions
{
    public function index(Request $request): View
    {
        $user = $request->user();
        abort_unless($user instanceof User, 401);
        $database = StandaloneAccess::sessionStore();
        $sessions = $database?->table((string) config('session.table', 'sessions'))
            ->where('user_id', (string) $user->getKey())
            ->orderByDesc('last_activity')
            ->get() ?? collect();

        return view()->file(__DIR__.'/../../../resources/views/auth/sessions.blade.php', [
            'sessions' => $sessions,
            'currentSessionId' => $request->session()->getId(),
            'enumerable' => $database !== null,
        ]);
    }

    public function destroy(Request $request, string $session): RedirectResponse
    {
        [$user, $database] = $this->confirmedUserAndStore($request);

        if (hash_equals($request->session()->getId(), $session)) {
            abort(422);
        }

        $deleted = $database->table((string) config('session.table', 'sessions'))
            ->where('id', $session)
            ->where('user_id', (string) $user->getKey())
            ->delete();

        abort_unless($deleted === 1, 404);

        return back()->with('status', 'session-revoked');
    }

    public function destroyOthers(Request $request): RedirectResponse
    {
        [$user, $database] = $this->confirmedUserAndStore($request);

        $database->table((string) config('session.table', 'sessions'))
            ->where('user_id', (string) $user->getKey())
            ->where('id', '!=', $request->session()->getId())
            ->delete();

        return back()->with('status', 'other-sessions-revoked');
    }

    /** @return array{User, ConnectionInterface} */
    private function confirmedUserAndStore(Request $request): array
    {
        $input = $request->validate(['password' => ['required', 'string', 'max:255']]);
        $user = $request->user();
        abort_unless($user instanceof User, 401);

        if (! StandaloneAccess::passwordMatches($user, $input['password'])) {
            throw ValidationException::withMessages(['password' => 'The password is incorrect.']);
        }

        $database = StandaloneAccess::sessionStore();
        abort_if($database === null, 409, 'The configured session driver cannot enumerate sessions.');

        return [$user, $database];
    }
}
