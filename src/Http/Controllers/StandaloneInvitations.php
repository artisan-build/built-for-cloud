<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\Actions\AcceptHumanInvitation;
use ArtisanBuild\BuiltForCloud\Console\ConsoleReturnTo;
use ArtisanBuild\BuiltForCloud\Invitation;
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
        try {
            $input = $request->validate([
                'token' => ['required', 'string', 'max:255'],
                'name' => ['required', 'string', 'max:255'],
                'password' => ['required', 'string', 'min:12', 'max:255', 'confirmed'],
                'intended' => ['nullable', 'string', 'max:2048'],
            ]);
        } catch (ValidationException $exception) {
            return $this->validationFailure($request, $exception);
        }

        try {
            $user = $accept($input['token'], $input['name'], $input['password']);
        } catch (RuntimeException|QueryException) {
            return $this->validationFailure(
                $request,
                ValidationException::withMessages(['token' => 'This invitation is not available.']),
            );
        }

        Auth::guard('web')->login($user, false);
        $request->session()->regenerate();
        $request->session()->put(StandaloneAccess::SESSION_VERSION_KEY, $user->auth_session_version);
        $user->forceFill(['last_authenticated_at' => now()])->save();

        return redirect()->to(ConsoleReturnTo::firstRelative([$input['intended'] ?? null]));
    }

    private function validationFailure(Request $request, ValidationException $exception): RedirectResponse
    {
        $redirectTo = $this->retryUrl($request);
        $safeInput = $request->only(['name', 'intended']);

        $request->query->remove('token');
        $request->request->remove('token');

        if ($request->isJson()) {
            $request->json()->remove('token');
        }

        $request->session()->forget(['_previous.url', '_previous.route']);

        if ($request->expectsJson()) {
            throw $exception;
        }

        return redirect($redirectTo)
            ->withInput($safeInput)
            ->withErrors($exception->errors());
    }

    private function retryUrl(Request $request): string
    {
        $token = $request->input('token');

        if (! is_string($token) || $token === '' || mb_strlen($token) > 255) {
            return route('bfc.login', absolute: false);
        }

        $invitation = Invitation::query()->where('token', Invitation::hashToken($token))->first();
        $parameters = ['token' => $token];

        if ($invitation instanceof Invitation && is_string($invitation->email)) {
            $parameters['email'] = $invitation->email;
        }

        $intended = ConsoleReturnTo::relative($request->input('intended'));

        if ($intended !== null) {
            $parameters['intended'] = $intended;
        }

        return route('bfc.invitations.accept', $parameters, false);
    }
}
