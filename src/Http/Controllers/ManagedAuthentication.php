<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\BrowserCredentialAuthorizationStore;
use ArtisanBuild\BuiltForCloud\Exceptions\ManagedAuthRefused;
use ArtisanBuild\BuiltForCloud\ManagedAuthConnection;
use ArtisanBuild\BuiltForCloud\ManagedHandoff;
use ArtisanBuild\BuiltForCloud\ManagedMembershipResponses;
use ArtisanBuild\BuiltForCloud\ManagedReturnTo;
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
            $authorizationUrl = $handoff->begin($request);

            if ($request->query->has('intended')) {
                $request->session()->put(ManagedHandoff::SESSION_INTENDED_KEY, ManagedReturnTo::firstRelative([
                    $request->query('intended'),
                    route('bfc.dashboard', absolute: false),
                ]));
            } else {
                $request->session()->forget(ManagedHandoff::SESSION_INTENDED_KEY);
            }

            return redirect()->away($authorizationUrl);
        } catch (ManagedAuthRefused) {
            return $this->refusal();
        }
    }

    public function callback(
        Request $request,
        ManagedHandoff $handoff,
        ManagedMembershipResponses $responses,
        BrowserCredentialAuthorizationStore $authorizations,
    ): RedirectResponse|Response {
        try {
            $exchange = $handoff->exchange($request);

            $connection = ManagedAuthConnection::current();
            $user = $responses->applyExchange($connection, $exchange);

            if ($user === null) {
                throw new ManagedAuthRefused;
            }

            Auth::guard('web')->login($user, false);
            $authorizations->regenerate($request);
            $request->session()->put(StandaloneAccess::SESSION_VERSION_KEY, $user->auth_session_version);
            $request->session()->forget(ManagedHandoff::SESSION_NONCE_KEY);

            return redirect()->to(ManagedReturnTo::firstRelative([
                $request->session()->pull(ManagedHandoff::SESSION_INTENDED_KEY),
                route('bfc.dashboard', absolute: false),
            ]));
        } catch (ManagedAuthRefused) {
            return $this->refusal();
        }
    }

    private function refusal(): Response
    {
        return response('Not Found', 404)->header('Content-Type', 'text/plain; charset=UTF-8');
    }
}
