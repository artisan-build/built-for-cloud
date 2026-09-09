<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\Actions\AcceptHumanInvitation;
use ArtisanBuild\BuiltForCloud\Console\ConsoleReturnTo;
use ArtisanBuild\BuiltForCloud\Invitation;
use ArtisanBuild\BuiltForCloud\StandaloneAccess;
use ArtisanBuild\BuiltForCloud\StandaloneHandoff;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Contracts\View\View;
use Illuminate\Database\QueryException;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;
use RuntimeException;
use SensitiveParameter;

final class StandaloneInvitations
{
    public function handoff(
        Request $request,
        #[SensitiveParameter] string $token,
        StandaloneHandoff $handoff,
    ): RedirectResponse|Response {
        $this->refuseSession($request);
        $invitation = $this->invitation($token);

        if (! $invitation instanceof Invitation) {
            return response('', Response::HTTP_NOT_FOUND);
        }

        $handoff->issue(
            StandaloneHandoff::INVITATION,
            $token,
            ConsoleReturnTo::relative($request->query('intended')),
        );

        return redirect()->route('bfc.invitations.accept.form')
            ->withHeaders(['Referrer-Policy' => 'no-referrer']);
    }

    public function show(Request $request, StandaloneHandoff $handoff): View|Response
    {
        $payload = $handoff->read($request, StandaloneHandoff::INVITATION);
        $invitation = $payload === null ? null : $this->invitation($payload['token']);

        if (! $invitation instanceof Invitation) {
            return response('', Response::HTTP_NOT_FOUND);
        }

        return view()->file(__DIR__.'/../../../resources/views/auth/accept-invitation.blade.php', [
            'token' => $payload['token'],
            'email' => $invitation->email,
            'intended' => $payload['intended'],
        ]);
    }

    public function store(
        Request $request,
        AcceptHumanInvitation $accept,
        StandaloneHandoff $handoff,
    ): RedirectResponse {
        $payload = $handoff->read($request, StandaloneHandoff::INVITATION);
        $submittedToken = $request->input('token');

        if ($payload === null
            || ! is_string($submittedToken)
            || ! hash_equals($payload['token'], $submittedToken)) {
            return $this->validationFailure(
                $request,
                ValidationException::withMessages(['token' => 'This invitation is not available.']),
                $handoff,
                true,
            );
        }

        try {
            $input = $request->validate([
                'name' => ['required', 'string', 'max:255'],
                'password' => ['required', 'string', 'min:12', 'max:255', 'confirmed'],
                'intended' => ['nullable', 'string', 'max:2048'],
            ]);
        } catch (ValidationException $exception) {
            return $this->validationFailure($request, $exception, $handoff);
        }

        try {
            $user = $accept($payload['token'], $input['name'], $input['password']);
        } catch (RuntimeException|QueryException) {
            return $this->validationFailure(
                $request,
                ValidationException::withMessages(['token' => 'This invitation is not available.']),
                $handoff,
                true,
            );
        }

        Auth::guard('web')->login($user, false);
        $request->session()->regenerate();
        $request->session()->put(StandaloneAccess::SESSION_VERSION_KEY, $user->auth_session_version);
        $user->forceFill(['last_authenticated_at' => now()])->save();
        $handoff->expire(StandaloneHandoff::INVITATION);

        return redirect()->to(ConsoleReturnTo::firstRelative([$payload['intended'], $input['intended'] ?? null]));
    }

    private function validationFailure(
        Request $request,
        ValidationException $exception,
        StandaloneHandoff $handoff,
        bool $terminal = false,
    ): RedirectResponse {
        $safeInput = $request->only(['name', 'intended']);

        $request->query->remove('token');
        $request->request->remove('token');

        if ($request->isJson()) {
            $request->json()->remove('token');
        }

        if ($terminal) {
            $handoff->expire(StandaloneHandoff::INVITATION);
        }

        if ($request->expectsJson()) {
            throw $exception;
        }

        return redirect()->route('bfc.invitations.accept.form')
            ->withInput($safeInput)
            ->withErrors($exception->errors());
    }

    private function invitation(#[SensitiveParameter] string $token): ?Invitation
    {
        if ($token === '' || mb_strlen($token) > 255) {
            return null;
        }

        $invitation = Invitation::query()
            ->where('token', Invitation::hashToken($token))
            ->pending()
            ->first();
        $role = $invitation instanceof Invitation ? UserRole::tryFrom((string) $invitation->role) : null;

        return $invitation instanceof Invitation
            && is_string($invitation->email)
            && $invitation->email !== ''
            && $invitation->expires_at !== null
            && $invitation->expires_at->isFuture()
            && in_array($role, [UserRole::Admin, UserRole::Member], true)
            && ! User::query()->whereRaw('lower(email) = ?', [$invitation->email])->exists()
                ? $invitation
                : null;
    }

    private function refuseSession(Request $request): void
    {
        if ($request->hasSession()) {
            throw new RuntimeException('Standalone bearer handoff routes cannot run with a session.');
        }
    }
}
