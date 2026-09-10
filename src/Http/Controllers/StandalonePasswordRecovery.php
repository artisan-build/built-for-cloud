<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\Actions\RequestStandalonePasswordReset;
use ArtisanBuild\BuiltForCloud\StandaloneAccess;
use ArtisanBuild\BuiltForCloud\StandaloneHandoff;
use ArtisanBuild\BuiltForCloud\User;
use Carbon\CarbonImmutable;
use Illuminate\Contracts\View\View;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use RuntimeException;
use SensitiveParameter;
use Throwable;

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

    public function handoff(
        Request $request,
        #[SensitiveParameter] string $token,
        StandaloneHandoff $handoff,
    ): RedirectResponse|Response {
        $this->refuseSession($request);
        $user = $this->resetUser($token);

        if (! $user instanceof User) {
            return response('', Response::HTTP_NOT_FOUND);
        }

        $handoff->issue(StandaloneHandoff::PASSWORD_RESET, $token);

        return redirect()->route('bfc.password.reset.form')
            ->withHeaders(['Referrer-Policy' => 'no-referrer']);
    }

    public function edit(Request $request, StandaloneHandoff $handoff): View|Response
    {
        $payload = $handoff->read($request, StandaloneHandoff::PASSWORD_RESET);
        $user = $payload === null ? null : $this->resetUser($payload['token']);

        if (! $user instanceof User) {
            return response('', Response::HTTP_NOT_FOUND);
        }

        return view()->file(__DIR__.'/../../../resources/views/auth/reset-password.blade.php', [
            'token' => $payload['token'],
            'email' => $user->email,
        ]);
    }

    public function update(Request $request, StandaloneHandoff $handoff): RedirectResponse
    {
        $payload = $handoff->read($request, StandaloneHandoff::PASSWORD_RESET);
        $submittedToken = $request->input('token');

        if ($payload === null
            || ! is_string($submittedToken)
            || ! hash_equals($payload['token'], $submittedToken)) {
            return $this->validationFailure(
                $request,
                ValidationException::withMessages(['email' => 'This reset request is not available.']),
                $handoff,
                true,
            );
        }

        try {
            $input = $request->validate([
                'email' => ['required', 'string', 'max:255'],
                'password' => ['required', 'string', 'min:12', 'max:255', 'confirmed'],
            ]);
        } catch (ValidationException $exception) {
            return $this->validationFailure($request, $exception, $handoff);
        }
        $email = StandaloneAccess::normalizeEmail($input['email']);
        $lifetime = max(5, min(1440, (int) config('built-for-cloud.standalone.password_reset_minutes', 60)));

        $resetUserId = null;

        try {
            DB::transaction(function () use ($email, $payload, $input, $lifetime, &$resetUserId): void {
                $user = User::query()->whereRaw('lower(email) = ?', [$email])->lockForUpdate()->first();
                $reset = $user instanceof User
                    ? DB::table('password_reset_tokens')->where('email', $user->email)->lockForUpdate()->first()
                    : null;

                if (! $user instanceof User
                    || ! StandaloneAccess::userCanReceiveRecovery($user)
                    || ! is_object($reset)
                    || ! is_string($reset->token ?? null)
                    || ! hash_equals($reset->token, hash('sha256', $payload['token']))
                    || CarbonImmutable::parse((string) $reset->created_at)->addMinutes($lifetime)->isPast()) {
                    throw new RuntimeException('invalid reset');
                }

                $user->forceFill(['password' => Hash::make($input['password'])])->save();
                $resetUserId = (string) $user->getKey();
                StandaloneAccess::invalidateSessions($user);
                DB::table('password_reset_tokens')->where('email', $user->email)->delete();
            }, 3);
        } catch (RuntimeException) {
            return $this->validationFailure(
                $request,
                ValidationException::withMessages(['email' => 'This reset request is not available.']),
                $handoff,
                true,
            );
        }

        if ((string) Auth::guard('web')->id() === $resetUserId) {
            StandaloneAccess::endCurrentSession($request, Auth::guard('web'));
        }
        $handoff->expire(StandaloneHandoff::PASSWORD_RESET);

        return redirect()->route('bfc.login');
    }

    private function validationFailure(
        Request $request,
        ValidationException $exception,
        StandaloneHandoff $handoff,
        bool $terminal = false,
    ): RedirectResponse {
        $safeInput = $request->only(['email']);

        $request->query->remove('token');
        $request->request->remove('token');

        if ($request->isJson()) {
            $request->json()->remove('token');
        }

        if ($terminal) {
            $handoff->expire(StandaloneHandoff::PASSWORD_RESET);
        }

        if ($request->expectsJson()) {
            throw $exception;
        }

        return redirect()->route('bfc.password.reset.form')
            ->withInput($safeInput)
            ->withErrors($exception->errors());
    }

    private function resetUser(#[SensitiveParameter] string $token): ?User
    {
        if ($token === '' || mb_strlen($token) > 255) {
            return null;
        }

        $reset = DB::table('password_reset_tokens')->where('token', hash('sha256', $token))->first();
        $user = is_object($reset) && is_string($reset->email ?? null)
            ? User::query()->where('email', $reset->email)->first()
            : null;
        $lifetime = max(5, min(1440, (int) config('built-for-cloud.standalone.password_reset_minutes', 60)));

        try {
            $expired = ! is_object($reset)
                || ! is_string($reset->created_at ?? null)
                || CarbonImmutable::parse($reset->created_at)->addMinutes($lifetime)->isPast();
        } catch (Throwable) {
            return null;
        }

        return $user instanceof User && StandaloneAccess::userCanReceiveRecovery($user) && ! $expired
            ? $user
            : null;
    }

    private function refuseSession(Request $request): void
    {
        if ($request->hasSession()) {
            throw new RuntimeException('Standalone bearer handoff routes cannot run with a session.');
        }
    }
}
