<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Console\ConsoleGuardConfiguration;
use ArtisanBuild\BuiltForCloud\Console\ConsoleRole;
use ArtisanBuild\BuiltForCloud\Exceptions\SelfServiceUnavailable;
use ArtisanBuild\BuiltForCloud\PersonalCredentialSurface;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\SelfServiceDeclaration;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\User;
use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Route;

uses(RefreshDatabase::class);

/**
 * AC14 — D14 applied PER SURFACE, which is the whole point of it being a
 * resolved value rather than a blanket rule, and the whole point of the
 * ADMISSION/REFUSAL asymmetry.
 *
 * - A gate that can only act as the local human REFUSES a delegated
 *   session (`bfc.auth`, the personal-credentials surface), and refuses
 *   it BROADLY: whichever guard the route names. Refusing costs only
 *   convenience.
 * - A gate that CONSUMES the resolved principal (`bfc.admin`) admits a
 *   delegated `admin` — but only where that actor really is the acting
 *   principal, i.e. on a route the console guard governs. Admitting on
 *   one identity while the request acts as another is FLEET-C-02, and
 *   it is what the exactness rules out.
 *
 * The token gates (`bfc.token.admin`, `bfc.credential.admin`,
 * `bfc.ability`) are unaffected and are deliberately not touched: they
 * never consult a session principal at all, so there is no principal for
 * a delegated session to disagree with.
 */
beforeEach(function (): void {
    // The mounted personal surface needs an app declaration that can
    // derive a subject from the session; without one it refuses for a
    // different reason entirely and proves nothing about D14.
    config(['built-for-cloud.credentials.declaration' => SelfServiceDeclaration::class]);

    Route::middleware([StartSession::class, 'bfc.auth'])->get('/local-only', fn (): array => ['ok' => true]);

    // The app's own admin surface: guarded by the app's own session
    // guard, with no console scoping anywhere on it.
    Route::middleware([StartSession::class, 'bfc.admin'])->get('/admin-only', fn (): array => ['ok' => true]);

    // A CONSOLE admin surface — the shape PR5's chrome will mount:
    // the console guard governs the route, so the delegated actor is
    // what everything behind the gate acts as.
    Route::middleware([StartSession::class, 'bfc.console', 'auth:'.ConsoleGuardConfiguration::GUARD, 'bfc.admin'])
        ->get('/console-admin-only', fn (): array => ['ok' => true]);
});

function surfaceUser(bool $admin = false): User
{
    $user = User::query()->create([
        'name' => 'Local User',
        'email' => 'local@example.com',
        'password' => 'irrelevant',
    ]);

    if ($admin) {
        $user->forceFill(['is_admin' => true])->save();
    }

    return $user;
}

// ─── The local-only surface REFUSES a delegated principal ───────────────────

it('refuses a delegated session on a local-only gate instead of acting as the local user', function (): void {
    $user = surfaceUser();
    $actor = consoleActor();

    $this->actingAs($user)->withSession(consoleSessionState($actor));

    $this->getJson('/local-only')->assertStatus(403);
});

it('still admits the local user on that gate when no delegated session is live', function (): void {
    $this->actingAs(surfaceUser());

    $this->getJson('/local-only')->assertOk();
});

it('refuses a delegated session on the personal-credentials surface itself', function (): void {
    $user = surfaceUser();
    $actor = consoleActor();

    $this->actingAs($user)->withSession(consoleSessionState($actor));

    // The class is public API a host app's own screen calls directly,
    // without the package middleware in front of it, so it carries its
    // own refusal — on the listing verb, whose subject comes from the
    // app's declaration and would otherwise never ask who is calling.
    expect(fn (): array => app(PersonalCredentialSurface::class)->mine(request()))
        ->toThrow(SelfServiceUnavailable::class, 'no personal identity');
});

it('refuses a delegated session on the mounted personal-credentials route', function (): void {
    $user = surfaceUser();
    $actor = consoleActor();

    $this->actingAs($user)->withSession(consoleSessionState($actor));

    $this->getJson('/bfc/me/credentials')->assertStatus(403);
});

// ─── A refused console session is TERMINAL, never a fallthrough ─────────────

it('refuses /bfc/me/credentials after a console refusal, past the limiter that already cached the local user', function (): void {
    $user = surfaceUser();

    // Baseline: with no console session the SAME request succeeds, so
    // the local user is genuinely resolvable on this path.
    $this->actingAs($user);
    $this->getJson('/bfc/me/credentials')->assertOk();

    // Now with a capped delegated session. The `bfc-personal` limiter
    // runs BEFORE the gate and calls $request->user(), so the local
    // session guard is already holding that user in memory — flushing
    // session storage cannot erase that, and the refusal has to beat
    // the cache.
    $actor = consoleActor();

    $this->actingAs($user)->withSession(consoleSessionState($actor, CarbonImmutable::now()->subMinutes(121)->getTimestamp()));

    $this->getJson('/bfc/me/credentials')->assertStatus(401);
});

it('refuses the admin gate after a console refusal rather than falling back to a local admin', function (): void {
    $user = surfaceUser(admin: true);
    $actor = consoleActor(role: ConsoleRole::Admin);

    $this->actingAs($user)->withSession(consoleSessionState($actor, CarbonImmutable::now()->subMinutes(121)->getTimestamp()));

    $this->getJson('/admin-only')->assertStatus(403);
});

// ─── The admin gate CONSUMES the resolved principal, exactly ────────────────

it('admits a delegated actor whose own handoff carried the admin role', function (): void {
    $actor = consoleActor(role: ConsoleRole::Admin);

    $this->withSession(consoleSessionState($actor));

    $this->getJson('/console-admin-only')->assertOk();
});

it('refuses a delegated actor whose own handoff carried the member role', function (): void {
    $actor = consoleActor(role: ConsoleRole::Member);

    $this->withSession(consoleSessionState($actor));

    $this->getJson('/console-admin-only')->assertStatus(403);
});

it('does not let a later admin handoff promote a live member session past the admin gate', function (): void {
    $actor = consoleActor(role: ConsoleRole::Member);

    $this->withSession(consoleSessionState($actor));

    consoleActor(role: ConsoleRole::Admin);

    $this->getJson('/console-admin-only')->assertStatus(403);
});

it('lets the delegated admin win the console admin gate over a non-admin local session', function (): void {
    // Both live: the local user is not an admin, the delegated actor is.
    // The route's guard is the console guard, so the delegated principal
    // governs — and the gate is admitting the SAME principal everything
    // behind it acts as.
    $this->actingAs(surfaceUser(admin: false));

    $actor = consoleActor(role: ConsoleRole::Admin);

    $this->withSession(consoleSessionState($actor));

    $this->getJson('/console-admin-only')->assertOk();
});

it('refuses when a delegated member session outranks a local admin', function (): void {
    // The mirror image, and the one that matters: a local ADMIN session
    // must not lend its standing to a delegated member. The delegated
    // principal governs, and it is not an admin.
    $this->actingAs(surfaceUser(admin: true));

    $actor = consoleActor(role: ConsoleRole::Member);

    $this->withSession(consoleSessionState($actor));

    $this->getJson('/console-admin-only')->assertStatus(403);
});

it('refuses a delegated admin on an admin gate the console guard does not govern', function (): void {
    // ADMISSION IS EXACT. This route is guarded by the app's own session
    // guard, so `$request->user()` behind the gate is the local user —
    // admitting the delegated admin here would authorize one identity
    // and then act as another. It is a 403 rather than a fall-through to
    // the local admin, too: D14 says the delegated principal governs, so
    // a local admin's standing is not lent to it.
    $this->actingAs(surfaceUser(admin: true));

    $actor = consoleActor(role: ConsoleRole::Admin);

    $this->withSession(consoleSessionState($actor));

    $this->getJson('/admin-only')->assertStatus(403);
});

it('still admits a local admin on the admin gate when no delegated session is live', function (): void {
    $this->actingAs(surfaceUser(admin: true));

    $this->getJson('/admin-only')->assertOk();
});

it('still refuses a local non-admin on the admin gate', function (): void {
    $this->actingAs(surfaceUser(admin: false));

    $this->getJson('/admin-only')->assertStatus(403);
});
