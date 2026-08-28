<?php

declare(strict_types=1);

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
