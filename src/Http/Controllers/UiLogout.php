<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\BrowserCredentialAuthorizationStore;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

final class UiLogout
{
    public function __invoke(Request $request, BrowserCredentialAuthorizationStore $authorizations): RedirectResponse
    {
        Auth::guard('web')->logout();
        $authorizations->clear($request);
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect()->to('/');
    }
}
