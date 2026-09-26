<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| Built for Cloud web routes
|--------------------------------------------------------------------------
|
| The browser half of the package: the landing page, sign-in and account
| recovery, members and sessions, the dashboard, settings (the package UI),
| and token management. They
| are loaded in every app, because every Built for Cloud app has a UI.
|
| Groups carry a `bfc_family` attribute the service provider reads after
| loading this file, to hold each family to the ownership rules its
| controllers rely on (StandaloneRouteOwnership): `landing`, `ui` and
| `standalone` routes keep their reserved names and shapes, and every family
| but `landing` keeps its package middleware. The two `bfc_bearer` pages carry
| a bearer token in the path and never start a session.
|
| Browser routes ride the full session stack: the app's `web` group when it
| has one, the equivalent session middleware when it does not, so cookie
| sessions actually start and the MUTATING verbs are CSRF-protected. Without
| it a session-riding forgery on a logged-in user's browser could mint,
| rotate or revoke credentials.
|
*/

use ArtisanBuild\BuiltForCloud\Http\Controllers\Dashboard;
use ArtisanBuild\BuiltForCloud\Http\Controllers\DeviceAuthorizations;
use ArtisanBuild\BuiltForCloud\Http\Controllers\InstallationCredentials;
use ArtisanBuild\BuiltForCloud\Http\Controllers\LoopbackAuthorizations;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManagedAuthentication;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ManageTransitions;
use ArtisanBuild\BuiltForCloud\Http\Controllers\PackageAssets;
use ArtisanBuild\BuiltForCloud\Http\Controllers\PersonalCredentials;
use ArtisanBuild\BuiltForCloud\Http\Controllers\StandaloneAuthentication;
use ArtisanBuild\BuiltForCloud\Http\Controllers\StandaloneInvitations;
use ArtisanBuild\BuiltForCloud\Http\Controllers\StandaloneMemberships;
use ArtisanBuild\BuiltForCloud\Http\Controllers\StandalonePasswordRecovery;
use ArtisanBuild\BuiltForCloud\Http\Controllers\StandaloneSessions;
use ArtisanBuild\BuiltForCloud\Http\Controllers\UiHome;
use ArtisanBuild\BuiltForCloud\Http\Controllers\UiInstallationCredentials;
use ArtisanBuild\BuiltForCloud\Http\Controllers\UiLogout;
use ArtisanBuild\BuiltForCloud\Http\Controllers\UiPersonalCredentials;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureManagedAuthority;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureStandaloneAuthority;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUiAuthority;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAuthenticated;
use ArtisanBuild\BuiltForCloud\Http\Middleware\ExpireStandaloneHandoffOnRefusal;
use ArtisanBuild\BuiltForCloud\LandingPageRegistrar;
use ArtisanBuild\BuiltForCloud\ManagedTransitionDirection;
use Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse;
use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Routing\Router;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Route;
use Illuminate\View\Middleware\ShareErrorsFromSession;

$browser = Route::hasMiddlewareGroup('web') ? ['web'] : [
    EncryptCookies::class,
    AddQueuedCookiesToResponse::class,
    StartSession::class,
    ShareErrorsFromSession::class,
    PreventRequestForgery::class,
];
$authorizationUser = EnsureUserIsAuthenticated::class.':'.EnsureUserIsAuthenticated::DEFER_MANAGED_AUTHORITY;

Route::group(['bfc_family' => 'landing'], function (): void {
    App::make(LandingPageRegistrar::class)->mount(App::make(Router::class));
});

Route::get('/bfc/assets/{path}', PackageAssets::class)
    ->where('path', PackageAssets::PATTERN)
    ->name('bfc.assets');

// Device and loopback authorization: the browser halves, where a signed-in
// person approves a CLI's request. The token halves are in routes/api.php.
Route::group(['bfc_family' => 'authorization'], function () use ($browser, $authorizationUser): void {
    Route::post('/bfc/device-authorizations', [DeviceAuthorizations::class, 'store'])
        ->middleware([...$browser, $authorizationUser, 'throttle:bfc-authorization-start'])
        ->name('bfc.device.start');
    Route::get('/bfc/device', [DeviceAuthorizations::class, 'show'])
        ->middleware([...$browser, $authorizationUser])
        ->name('bfc.device.show');
    Route::post('/bfc/device', [DeviceAuthorizations::class, 'decide'])
        ->middleware([...$browser, $authorizationUser, 'throttle:bfc-authorization-decision'])
        ->name('bfc.device.decide');
    Route::get('/bfc/loopback/authorize', [LoopbackAuthorizations::class, 'show'])
        ->middleware([...$browser, $authorizationUser, 'throttle:bfc-authorization-start'])
        ->name('bfc.loopback.authorize');
    Route::post('/bfc/loopback/authorize', [LoopbackAuthorizations::class, 'decide'])
        ->middleware([...$browser, $authorizationUser, 'throttle:bfc-authorization-decision'])
        ->name('bfc.loopback.decide');
});

// The page every signed-in person lands on. What runs behind it is the app's
// choice (built-for-cloud.dashboard); the route, its name and its sign-in
// middleware are the package's.
Route::group(['bfc_family' => 'dashboard'], function () use ($browser): void {
    Route::get('/dashboard', Config::string('built-for-cloud.dashboard', Dashboard::class))
        ->middleware([...$browser, EnsureUiAuthority::class, EnsureUserIsAuthenticated::class])
        ->name('bfc.dashboard');
});

Route::group(['bfc_family' => 'ui'], function () use ($browser): void {
    Route::get('/settings', UiHome::class)
        ->middleware([...$browser, EnsureUiAuthority::class, EnsureUserIsAuthenticated::class])
        ->name('bfc.ui.home');
    Route::post('/settings/logout', UiLogout::class)
        ->middleware([...$browser, EnsureUiAuthority::class, EnsureUserIsAuthenticated::class])
        ->name('bfc.ui.logout');

    $credentialScreens = ['throttle:bfc-personal', ...$browser, EnsureUiAuthority::class, EnsureUserIsAuthenticated::class];
    Route::get('/settings/credentials/personal', [UiPersonalCredentials::class, 'index'])
        ->middleware($credentialScreens)
        ->name('bfc.ui.personal-credentials.index');
    Route::post('/settings/credentials/personal', [UiPersonalCredentials::class, 'store'])
        ->middleware($credentialScreens)
        ->name('bfc.ui.personal-credentials.store');
    Route::post('/settings/credentials/personal/{id}/rotate', [UiPersonalCredentials::class, 'rotate'])
        ->middleware($credentialScreens)
        ->name('bfc.ui.personal-credentials.rotate');
    Route::delete('/settings/credentials/personal/{id}', [UiPersonalCredentials::class, 'destroy'])
        ->middleware($credentialScreens)
        ->name('bfc.ui.personal-credentials.destroy');
    Route::get('/settings/credentials/installation', [UiInstallationCredentials::class, 'index'])
        ->middleware($credentialScreens)
        ->name('bfc.ui.installation-credentials.index');
    Route::post('/settings/credentials/installation', [UiInstallationCredentials::class, 'store'])
        ->middleware($credentialScreens)
        ->name('bfc.ui.installation-credentials.store');
    Route::post('/settings/credentials/installation/{id}/rotate', [UiInstallationCredentials::class, 'rotate'])
        ->middleware($credentialScreens)
        ->name('bfc.ui.installation-credentials.rotate');
    Route::delete('/settings/credentials/installation/{id}', [UiInstallationCredentials::class, 'destroy'])
        ->middleware($credentialScreens)
        ->name('bfc.ui.installation-credentials.destroy');
});

Route::get('/bfc/managed/login', [ManagedAuthentication::class, 'create'])
    ->middleware([EnsureManagedAuthority::class, ...$browser])
    ->name('bfc.managed.login');
Route::get('/bfc/managed/callback', [ManagedAuthentication::class, 'callback'])
    ->middleware([EnsureManagedAuthority::class, ...$browser])
    ->name('bfc.managed.callback');

Route::middleware([...$browser, EnsureUserIsAuthenticated::class])->group(function (): void {
    Route::get('/bfc/transitions/{direction}/prepare', [ManageTransitions::class, 'index'])
        ->whereIn('direction', ManagedTransitionDirection::values())
        ->name('bfc.transitions.index');
    Route::post('/bfc/transitions/{direction}/prepare', [ManageTransitions::class, 'store'])
        ->whereIn('direction', ManagedTransitionDirection::values())
        ->name('bfc.transitions.store');
    Route::get('/bfc/transitions/proposals/{transition}', [ManageTransitions::class, 'edit'])
        ->name('bfc.transitions.edit');
    Route::put('/bfc/transitions/proposals/{transition}', [ManageTransitions::class, 'update'])
        ->name('bfc.transitions.update');
    Route::post('/bfc/transitions/proposals/{transition}/complete', [ManageTransitions::class, 'complete'])
        ->name('bfc.transitions.complete');
    Route::post('/bfc/transitions/proposals/{transition}/abandon', [ManageTransitions::class, 'abandon'])
        ->name('bfc.transitions.abandon');
});

Route::group(['bfc_family' => 'standalone'], function () use ($browser, $authorizationUser): void {
    $handoff = [
        EncryptCookies::class,
        AddQueuedCookiesToResponse::class,
        ExpireStandaloneHandoffOnRefusal::class,
    ];
    $handoffSession = [...$handoff, EnsureStandaloneAuthority::class, ...$browser];

    Route::get('/bfc/reset-password', [StandalonePasswordRecovery::class, 'edit'])
        ->middleware($handoffSession)
        ->name('bfc.password.reset.form');
    Route::post('/bfc/reset-password', [StandalonePasswordRecovery::class, 'update'])
        ->middleware([...$handoffSession, 'throttle:bfc-password-reset'])
        ->name('bfc.password.update');
    Route::get('/bfc/invitations/accept', [StandaloneInvitations::class, 'show'])
        ->middleware($handoffSession)
        ->name('bfc.invitations.accept.form');
    Route::post('/bfc/invitations/accept', [StandaloneInvitations::class, 'store'])
        ->middleware([...$handoffSession, 'throttle:bfc-invitation-accept'])
        ->name('bfc.invitations.accept.store');

    Route::group(['bfc_bearer' => true], function () use ($handoff): void {
        $bearerPage = [...$handoff, 'throttle:bfc-bearer-handoff', EnsureStandaloneAuthority::class];

        Route::get('/bfc/reset-password/{token}', [StandalonePasswordRecovery::class, 'handoff'])
            ->middleware($bearerPage)
            ->withoutMiddleware([StartSession::class])
            ->name('bfc.password.reset');
        Route::get('/bfc/invitations/{token}', [StandaloneInvitations::class, 'handoff'])
            ->middleware($bearerPage)
            ->withoutMiddleware([StartSession::class])
            ->name('bfc.invitations.accept');
    });

    Route::middleware([EnsureStandaloneAuthority::class, ...$browser])->group(function (): void {
        Route::get('/bfc/login', [StandaloneAuthentication::class, 'create'])
            ->name('bfc.login');
        Route::post('/bfc/login', [StandaloneAuthentication::class, 'store'])
            ->middleware('throttle:bfc-login')
            ->name('bfc.login.store');
        Route::get('/bfc/forgot-password', [StandalonePasswordRecovery::class, 'create'])
            ->name('bfc.password.request');
        Route::post('/bfc/forgot-password', [StandalonePasswordRecovery::class, 'store'])
            ->middleware('throttle:bfc-password-reset')
            ->name('bfc.password.email');
    });

    Route::middleware([EnsureUiAuthority::class, ...$browser, $authorizationUser, EnsureStandaloneAuthority::class])->group(function (): void {
        Route::get('/bfc/members', [StandaloneMemberships::class, 'index'])
            ->name('bfc.members.index');
        Route::post('/bfc/members/invitations', [StandaloneMemberships::class, 'invite'])
            ->middleware('throttle:bfc-invitation-issue')
            ->name('bfc.members.invitations.store');
        Route::put('/bfc/members/{user}/role', [StandaloneMemberships::class, 'role'])
            ->name('bfc.members.role.update');
        Route::delete('/bfc/members/{user}', [StandaloneMemberships::class, 'deactivate'])
            ->name('bfc.members.destroy');

        Route::get('/bfc/me/sessions', [StandaloneSessions::class, 'index'])
            ->name('bfc.sessions.index');
        Route::delete('/bfc/me/sessions/others', [StandaloneSessions::class, 'destroyOthers'])
            ->middleware('throttle:bfc-session-confirm')
            ->name('bfc.sessions.destroy-others');
        Route::delete('/bfc/me/sessions/{session}', [StandaloneSessions::class, 'destroy'])
            ->middleware('throttle:bfc-session-confirm')
            ->name('bfc.sessions.destroy');
        Route::post('/bfc/logout', [StandaloneAuthentication::class, 'destroy'])
            ->name('bfc.logout');
    });
});

// The personal-credentials surface (PRD 1.17): the SAME verbs as the
// operator credential API, session-authenticated and scoped to the caller's
// OWN credentials. Its gate is the session, not an operator ability — the app
// supplies the authenticated human — and the subject is derived SERVER-SIDE
// from that session by the app's declaration (SEC-V3-07), never from anything
// in the request. `bfc.auth` runs the offboarding kill too, so an offboarded
// user's surviving session cannot reach the screen (PRD 1.15).
Route::group(['bfc_family' => 'personal-credentials'], function () use ($browser): void {
    Route::get('/bfc/me/credentials', [PersonalCredentials::class, 'index'])
        ->middleware(['throttle:bfc-personal', ...$browser, EnsureUserIsAuthenticated::class]);
    Route::post('/bfc/me/credentials', [PersonalCredentials::class, 'store'])
        ->middleware(['throttle:bfc-personal', ...$browser, EnsureUserIsAuthenticated::class]);
    Route::delete('/bfc/me/credentials/{id}', [PersonalCredentials::class, 'destroy'])
        ->middleware(['throttle:bfc-personal', ...$browser, EnsureUserIsAuthenticated::class]);
});

Route::group(['bfc_family' => 'installation-credentials'], function () use ($browser): void {
    Route::get('/bfc/installation/credentials', [InstallationCredentials::class, 'index'])
        ->middleware(['throttle:bfc-personal', ...$browser, EnsureUserIsAuthenticated::class]);
    Route::post('/bfc/installation/credentials', [InstallationCredentials::class, 'store'])
        ->middleware(['throttle:bfc-personal', ...$browser, EnsureUserIsAuthenticated::class]);
    Route::post('/bfc/installation/credentials/{id}/rotate', [InstallationCredentials::class, 'rotate'])
        ->middleware(['throttle:bfc-personal', ...$browser, EnsureUserIsAuthenticated::class]);
    Route::delete('/bfc/installation/credentials/{id}', [InstallationCredentials::class, 'destroy'])
        ->middleware(['throttle:bfc-personal', ...$browser, EnsureUserIsAuthenticated::class]);
});
