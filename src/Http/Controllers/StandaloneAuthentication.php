<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\Console\ConsoleReturnTo;
use ArtisanBuild\BuiltForCloud\StandaloneAccess;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Contracts\View\View;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;

final class StandaloneAuthentication
{
    public function create(Request $request): View
    {
        return view()->file(__DIR__.'/../../../resources/views/auth/login.blade.php', [
            'intended' => ConsoleReturnTo::relative($request->query('intended')),
        ]);
    }

    public function store(Request $request): RedirectResponse
    {
        $credentials = $request->validate([
            'email' => ['required', 'string', 'max:255'],
            'password' => ['required', 'string', 'max:255'],
            'intended' => ['nullable', 'string', 'max:2048'],
        ]);
        $email = StandaloneAccess::normalizeEmail($credentials['email']);
        $user = User::query()->whereRaw('lower(email) = ?', [$email])->first();

        if (! $user instanceof User
            || ! StandaloneAccess::passwordMatches($user, $credentials['password'])) {
            throw ValidationException::withMessages(['email' => __('auth.failed')]);
        }

        Auth::guard('web')->login($user, false);
        $request->session()->regenerate();
        $request->session()->put(StandaloneAccess::SESSION_VERSION_KEY, $user->auth_session_version);
        $user->forceFill(['last_authenticated_at' => now()])->save();

        return redirect()->to(ConsoleReturnTo::firstRelative([$credentials['intended'] ?? null]));
    }

    public function destroy(Request $request): RedirectResponse
    {
        Auth::guard('web')->logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect()->route('bfc.login');
    }
}
