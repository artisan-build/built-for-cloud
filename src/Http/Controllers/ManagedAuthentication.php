<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\Exceptions\ManagedAuthRefused;
use ArtisanBuild\BuiltForCloud\ManagedAuthConnection;
use ArtisanBuild\BuiltForCloud\ManagedHandoff;
use ArtisanBuild\BuiltForCloud\ManagedIdentityUpsert;
use ArtisanBuild\BuiltForCloud\StandaloneAccess;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

final class ManagedAuthentication
{
    public function create(Request $request, ManagedHandoff $handoff): RedirectResponse|Response
    {
        try {
            return redirect()->away($handoff->begin($request));
        } catch (ManagedAuthRefused) {
            return $this->refusal();
        }
    }

    public function callback(
        Request $request,
        ManagedHandoff $handoff,
        ManagedIdentityUpsert $identities,
    ): RedirectResponse|Response {
        try {
            $exchange = $handoff->exchange($request);

            if ($exchange->membershipStatus !== 'active'
                || $exchange->connectionStatus !== 'active'
                || $exchange->contactEmailVerified !== true) {
                throw new ManagedAuthRefused;
            }

            $connection = ManagedAuthConnection::current();
            $user = $identities->upsert($connection, $exchange);

            if ($user->status !== 'active'
                || $user->role !== $exchange->role) {
                throw new ManagedAuthRefused;
            }

            Auth::guard('web')->login($user, false);
            $request->session()->regenerate();
            $request->session()->put(StandaloneAccess::SESSION_VERSION_KEY, $user->auth_session_version);
            $request->session()->forget(ManagedHandoff::SESSION_NONCE_KEY);

            return redirect()->to('/');
        } catch (ManagedAuthRefused) {
            return $this->refusal();
        }
    }

    private function refusal(): Response
    {
        return response('Not Found', 404)->header('Content-Type', 'text/plain; charset=UTF-8');
    }
}
