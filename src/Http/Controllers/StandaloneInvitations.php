<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\Actions\AcceptHumanInvitation;
use ArtisanBuild\BuiltForCloud\Console\ConsoleReturnTo;
use ArtisanBuild\BuiltForCloud\StandaloneAccess;
use Illuminate\Contracts\View\View;
use Illuminate\Database\QueryException;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;
use RuntimeException;

final class StandaloneInvitations
{
    public function show(Request $request, string $token): View
    {
        return view()->file(__DIR__.'/../../../resources/views/auth/accept-invitation.blade.php', [
            'token' => $token,
            'email' => StandaloneAccess::normalizeEmail((string) $request->query('email', '')),
            'intended' => ConsoleReturnTo::relative($request->query('intended')),
        ]);
    }

    public function store(Request $request, AcceptHumanInvitation $accept): RedirectResponse
    {
        $input = $request->validate([
            'token' => ['required', 'string', 'max:255'],
            'name' => ['required', 'string', 'max:255'],
            'password' => ['required', 'string', 'min:12', 'max:255', 'confirmed'],
            'intended' => ['nullable', 'string', 'max:2048'],
        ]);

        try {
            $user = $accept($input['token'], $input['name'], $input['password']);
        } catch (RuntimeException|QueryException) {
            throw ValidationException::withMessages(['token' => 'This invitation is not available.']);
        }

        Auth::guard('web')->login($user, false);
        $request->session()->regenerate();
        $request->session()->put(StandaloneAccess::SESSION_VERSION_KEY, $user->auth_session_version);
        $user->forceFill(['last_authenticated_at' => now()])->save();

        return redirect()->to(ConsoleReturnTo::firstRelative([$input['intended'] ?? null]));
    }
}
