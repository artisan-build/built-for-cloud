<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\WithCredentials;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Route;

uses(RefreshDatabase::class, WithCredentials::class);

/**
 * SEC-V3-10: the session/token precedence matrix, one test per cell.
 *
 * {no auth, session only, token only, both-matching, both-mismatched}
 *   × {token route, session route}
 */
beforeEach(function (): void {
    config([
        'auth.guards.bfc' => ['driver' => 'bfc', 'provider' => 'users'],
    ]);

    Route::middleware('auth:bfc')->get('/token-route', fn (): array => [
        'principal' => auth('bfc')->id(),
    ]);

    Route::middleware('auth:web')->get('/session-route', fn (): array => [
        'principal' => auth('web')->id(),
    ]);

    Route::middleware(['auth:bfc', 'bfc.ability:credential:read'])->get('/token-ability-route', fn (): array => [
        'principal' => auth('bfc')->id(),
    ]);
});

function precedenceUser(string $email = 'user@example.com'): User
{
    return User::query()->create([
        'name' => 'Precedence User',
        'email' => $email,
        'password' => 'irrelevant',
    ]);
}

// ─── Token route ────────────────────────────────────────────────────────────

it('token route × no auth → 401', function (): void {
    $this->getJson('/token-route')->assertStatus(401);
});

it('token route × session only → 401', function (): void {
    $this->actingAs(precedenceUser());

    $this->getJson('/token-route')->assertStatus(401);
});

it('token route × token only → 200 with the credential principal', function (): void {
    $minted = $this->mintCredential();

    $this->getJson('/token-route', ['Authorization' => $minted->bearerHeader()])
        ->assertStatus(200)
        ->assertJsonPath('principal', $minted->credential->id);
});

it('token route × both matching → 200, credential principal authoritative', function (): void {
    $user = precedenceUser();
    $minted = $this->mintCredential(['user_id' => (string) $user->id]);

    $this->actingAs($user);

    $this->getJson('/token-route', ['Authorization' => $minted->bearerHeader()])
        ->assertStatus(200)
        ->assertJsonPath('principal', $user->id);

    expect($minted->credential->refresh()->last_used_at)->not->toBeNull();
});

it('token route × both mismatched → 401, credential not stamped', function (): void {
    $sessionUser = precedenceUser('session@example.com');
    $boundUser = precedenceUser('bound@example.com');
    $minted = $this->mintCredential(['user_id' => (string) $boundUser->id]);

    $this->actingAs($sessionUser);

    $this->getJson('/token-route', ['Authorization' => $minted->bearerHeader()])
        ->assertStatus(401);

    expect($minted->credential->refresh()->last_used_at)->toBeNull();
});

// ─── Session route ──────────────────────────────────────────────────────────

it('session route × no auth → 401', function (): void {
    $this->getJson('/session-route')->assertStatus(401);
});

it('session route × session only → 200 with the session principal', function (): void {
    $user = precedenceUser();

    $this->actingAs($user);

    $this->getJson('/session-route')
        ->assertStatus(200)
        ->assertJsonPath('principal', $user->id);
});

it('session route × token only → 401, the bearer is never consumed', function (): void {
    $minted = $this->mintCredential();

    $this->getJson('/session-route', ['Authorization' => $minted->bearerHeader()])
        ->assertStatus(401);

    expect($minted->credential->refresh()->last_used_at)->toBeNull();
});

it('session route × both matching → 200 by session, the bearer is not stamped', function (): void {
    $user = precedenceUser();
    $minted = $this->mintCredential(['user_id' => (string) $user->id]);

    $this->actingAs($user);

    $this->getJson('/session-route', ['Authorization' => $minted->bearerHeader()])
        ->assertStatus(200)
        ->assertJsonPath('principal', $user->id);

    expect($minted->credential->refresh()->last_used_at)->toBeNull();
});

it("session route × both mismatched → 200 by session, the other user's credential is not stamped", function (): void {
    $sessionUser = precedenceUser('session@example.com');
    $otherUser = precedenceUser('other@example.com');
    $minted = $this->mintCredential(['user_id' => (string) $otherUser->id]);

    $this->actingAs($sessionUser);

    $this->getJson('/session-route', ['Authorization' => $minted->bearerHeader()])
        ->assertStatus(200)
        ->assertJsonPath('principal', $sessionUser->id);

    expect($minted->credential->refresh()->last_used_at)->toBeNull();
});

// ─── The session never widens token-route authority ─────────────────────────

it('does not widen credential abilities with a simultaneously present session', function (): void {
    $user = precedenceUser();
    $minted = $this->mintCredential([
        'purpose' => CredentialPurpose::Consumption,
        'subject_type' => SubjectType::UserPrincipal,
        'subject_ref' => 'user:'.$user->id,
        'user_id' => (string) $user->id,
        'abilities' => null,
    ]);

    $this->actingAs($user);

    $this->getJson('/token-ability-route', ['Authorization' => $minted->bearerHeader()])
        ->assertStatus(403);
});

it('does not let an unbound credential inherit anything from a session', function (): void {
    $user = precedenceUser();
    $minted = $this->mintCredential();

    $this->actingAs($user);

    // The unbound credential is the principal; the session adds nothing.
    $this->getJson('/token-route', ['Authorization' => $minted->bearerHeader()])
        ->assertStatus(200)
        ->assertJsonPath('principal', $minted->credential->id);
});

// ─── SEC-V3-10: the shipped single-session-guard matrix ─────────────────────
//
// The delegated-entry release once added a SECOND, session-based guard
// (`bfc-console`) to this matrix; it was retired in v0.17.0, and the
// guard no longer exists to configure. What the delegated rows pinned
// is now held structurally: no guard resolves a delegated actor, so no
// session principal can collide with a credential's `user_id`.

it('still rejects mismatched simultaneous principals', function (): void {
    $sessionUser = precedenceUser('session@example.com');
    $boundUser = precedenceUser('bound@example.com');
    $minted = $this->mintCredential(['user_id' => (string) $boundUser->id]);

    $this->actingAs($sessionUser);

    $this->getJson('/token-route', ['Authorization' => $minted->bearerHeader()])
        ->assertStatus(401);

    expect($minted->credential->refresh()->last_used_at)->toBeNull();
});

it('still rejects a mismatched local principal when the session guard is the local one', function (): void {
    // The same shape as above with the SHIPPED configuration, so the
    // exclusion above cannot be read as having weakened the rule it
    // sits next to.
    config(['built-for-cloud.credentials.session_guard' => 'web']);

    $sessionUser = precedenceUser('session@example.com');
    $boundUser = precedenceUser('bound@example.com');
    $minted = $this->mintCredential(['user_id' => (string) $boundUser->id]);

    $this->actingAs($sessionUser);

    $this->getJson('/token-route', ['Authorization' => $minted->bearerHeader()])
        ->assertStatus(401);
});

it('ability gate × configured guard name with no guard behind it → bounded 401, not a 500', function (): void {
    // An app can point built-for-cloud.credentials.guard at a name that
    // has no entry under auth.guards (a typo, a renamed guard). The
    // AuthManager raises out of guard() on exactly that case, and the
    // gate must turn a configuration error into the same fail-closed
    // 401 an unauthenticated request gets — the same ruling the vitals
    // gate carries and is tested under. Driven on the standalone shape
    // (the MCP wiring: bfc.ability alone, no auth:bfc in front), which
    // is the stack this middleware governs.
    config(['auth.guards.bfc' => null]);

    Route::middleware('bfc.ability:credential:read')->get('/ability-guardless', fn (): array => ['ok' => true]);

    $this->getJson('/ability-guardless')->assertStatus(401);
});
