<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\Actions\RequestStandalonePasswordReset;
use ArtisanBuild\BuiltForCloud\StandaloneAccess;
use ArtisanBuild\BuiltForCloud\User;
use Carbon\CarbonImmutable;
use Illuminate\Contracts\View\View;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use RuntimeException;

final class StandalonePasswordRecovery
{
    public function create(): View
    {
        return view()->file(__DIR__.'/../../../resources/views/auth/forgot-password.blade.php');
    }

    public function store(Request $request, RequestStandalonePasswordReset $reset): RedirectResponse
    {
        $reset((string) $request->input('email', ''));

        return back()->with('status', 'recovery-requested');
    }

    public function edit(Request $request, string $token): View
    {
        return view()->file(__DIR__.'/../../../resources/views/auth/reset-password.blade.php', [
            'token' => $token,
            'email' => StandaloneAccess::normalizeEmail((string) $request->query('email', '')),
        ]);
    }

    public function update(Request $request): RedirectResponse
    {
        $input = $request->validate([
            'token' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'max:255'],
            'password' => ['required', 'string', 'min:12', 'max:255', 'confirmed'],
        ]);
        $email = StandaloneAccess::normalizeEmail($input['email']);
        $lifetime = max(5, min(1440, (int) config('built-for-cloud.standalone.password_reset_minutes', 60)));

        try {
            DB::transaction(function () use ($email, $input, $lifetime): void {
                $user = User::query()->whereRaw('lower(email) = ?', [$email])->lockForUpdate()->first();
                $reset = $user instanceof User
                    ? DB::table('password_reset_tokens')->where('email', $user->email)->lockForUpdate()->first()
                    : null;

                if (! $user instanceof User
                    || ! StandaloneAccess::userCanReceiveRecovery($user)
                    || ! is_object($reset)
                    || ! is_string($reset->token ?? null)
                    || ! hash_equals($reset->token, hash('sha256', $input['token']))
                    || CarbonImmutable::parse((string) $reset->created_at)->addMinutes($lifetime)->isPast()) {
                    throw new RuntimeException('invalid reset');
                }

                $user->forceFill(['password' => Hash::make($input['password'])])->save();
                StandaloneAccess::invalidateSessions($user);
                DB::table('password_reset_tokens')->where('email', $user->email)->delete();
            }, 3);
        } catch (RuntimeException) {
            throw ValidationException::withMessages(['email' => 'This reset request is not available.']);
        }

        return redirect()->route('bfc.login');
    }
}
