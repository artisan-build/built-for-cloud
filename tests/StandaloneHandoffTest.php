<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\Invitation;
use ArtisanBuild\BuiltForCloud\StandaloneHandoff;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Cookie\CookieValuePrefix;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Symfony\Component\HttpFoundation\Cookie;

uses(RefreshDatabase::class);

function handoffResetUser(string $email = 'handoff-reset@example.test'): User
{
    $user = User::query()->create([
        'name' => 'Handoff Reset User',
        'email' => $email,
        'password' => Hash::make('original handoff password'),
    ]);
    $user->forceFill([
        'role' => UserRole::Member->value,
        'status' => 'active',
        'email_verified_at' => now(),
        'original_contact_email' => $email,
    ])->save();

    return $user;
}

function createResetHandoff(string $token, ?User $user = null): User
{
    $user ??= handoffResetUser();
    DB::table('password_reset_tokens')->insert([
        'email' => $user->email,
        'token' => hash('sha256', $token),
        'created_at' => now(),
    ]);

    return $user;
}

function createInvitationHandoff(string $token): Invitation
{
    return Invitation::factory()->create([
        'email' => 'handoff-invitee@example.test',
        'token' => Invitation::hashToken($token),
        'role' => UserRole::Member->value,
        'expires_at' => now()->addHour(),
    ]);
}

it('encrypts and scopes the reset handoff before rendering only the clean form', function (): void {
    $token = 'handoff-reset-'.bin2hex(random_bytes(32));
    $user = createResetHandoff($token);

    $response = $this->get(route('bfc.password.reset', ['token' => $token], false));
    $response->assertRedirect(route('bfc.password.reset.form'))
        ->assertHeader('Referrer-Policy', 'no-referrer')
        ->assertDontSee($token);
    $wireCookie = $response->getCookie(StandaloneHandoff::COOKIE, false);
    expect($wireCookie)->toBeInstanceOf(Cookie::class)
        ->and($wireCookie->getValue())->not->toContain($token)
        ->and($wireCookie->getPath())->toBe('/bfc/reset-password')
        ->and($wireCookie->isHttpOnly())->toBeTrue()
        ->and(strtolower((string) $wireCookie->getSameSite()))->toBe('lax')
        ->and($wireCookie->getExpiresTime())->toBeGreaterThan(now()->addMinute()->timestamp)
        ->toBeLessThanOrEqual(now()->addMinutes(15)->timestamp);

    $outer = app('encrypter')->decrypt($wireCookie->getValue(), false);
    $inner = CookieValuePrefix::remove($outer);
    $payload = json_decode(app('encrypter')->decrypt($inner, false), true, flags: JSON_THROW_ON_ERROR);
    expect($payload['purpose'])->toBe(StandaloneHandoff::PASSWORD_RESET)
        ->and($payload['token'])->toBe($token);

    $this->withCookie(StandaloneHandoff::COOKIE, $inner);
    $form = $this->get(route('bfc.password.reset.form', absolute: false));
    $form->assertOk()
        ->assertSeeHtml('data-testid="password-reset-form"')
        ->assertSee($user->email)
        ->assertSeeHtml('name="token" value="'.$token.'"');
    expect(substr_count((string) $form->getContent(), $token))->toBe(1);
});

it('preserves a valid handoff for correction and clears it with exact attributes on consume', function (): void {
    $token = 'correctable-reset-'.bin2hex(random_bytes(32));
    $user = createResetHandoff($token, handoffResetUser('correctable@example.test'));
    $handoff = $this->get(route('bfc.password.reset', ['token' => $token], false));
    $inner = $handoff->getCookie(StandaloneHandoff::COOKIE)?->getValue();
    expect($inner)->toBeString();
    $this->withCookie(StandaloneHandoff::COOKIE, $inner);

    $failure = $this->post('/bfc/reset-password', [
        'token' => $token,
        'email' => $user->email,
        'password' => 'short',
        'password_confirmation' => 'mismatch',
    ]);
    $failure->assertRedirect(route('bfc.password.reset.form'))
        ->assertSessionHasErrors(['password'])
        ->assertCookieMissing(StandaloneHandoff::COOKIE);
    $this->get('/bfc/reset-password')
        ->assertOk()
        ->assertSeeHtml('data-testid="password-reset-errors"');

    $success = $this->post('/bfc/reset-password', [
        'token' => $token,
        'email' => $user->email,
        'password' => 'corrected handoff password',
        'password_confirmation' => 'corrected handoff password',
    ]);
    $success->assertRedirect(route('bfc.login'))->assertCookieExpired(StandaloneHandoff::COOKIE);
    $expired = $success->getCookie(StandaloneHandoff::COOKIE, false);
    expect($expired)->toBeInstanceOf(Cookie::class)
        ->and($expired->getPath())->toBe('/bfc/reset-password')
        ->and($expired->isHttpOnly())->toBeTrue()
        ->and(strtolower((string) $expired->getSameSite()))->toBe('lax');
});

it('collapses missing tampered expired wrong-purpose and terminal handoffs to one refusal', function (): void {
    $resetToken = 'refused-reset-'.bin2hex(random_bytes(32));
    createResetHandoff($resetToken);
    $resetResponse = $this->get(route('bfc.password.reset', ['token' => $resetToken], false));
    $resetInner = $resetResponse->getCookie(StandaloneHandoff::COOKIE)?->getValue();
    expect($resetInner)->toBeString();

    $missing = $this->get('/bfc/reset-password');
    $missing->assertNotFound()->assertCookieExpired(StandaloneHandoff::COOKIE);

    $this->withCookie(StandaloneHandoff::COOKIE, 'tampered');
    $tampered = $this->get('/bfc/reset-password');
    $tampered->assertNotFound()->assertCookieExpired(StandaloneHandoff::COOKIE);

    $this->withCookie(StandaloneHandoff::COOKIE, $resetInner);
    $wrongPurpose = $this->get('/bfc/invitations/accept');
    $wrongPurpose->assertNotFound()->assertCookieExpired(StandaloneHandoff::COOKIE);
    $wrongPurposeCookies = collect($wrongPurpose->headers->getCookies())
        ->filter(fn (Cookie $cookie): bool => $cookie->getName() === StandaloneHandoff::COOKIE);
    expect($wrongPurposeCookies->contains(
        fn (Cookie $cookie): bool => $cookie->getPath() === '/bfc/invitations/accept'
            && $cookie->getExpiresTime() < now()->timestamp,
    ))->toBeTrue();

    $this->travel(11)->minutes();
    $this->withCookie(StandaloneHandoff::COOKIE, $resetInner);
    $expired = $this->get('/bfc/reset-password');
    $expired->assertNotFound()->assertCookieExpired(StandaloneHandoff::COOKIE);
    $this->travelBack();

    DB::table('password_reset_tokens')->delete();
    $this->withCookie(StandaloneHandoff::COOKIE, $resetInner);
    $terminal = $this->get('/bfc/reset-password');
    $terminal->assertNotFound()->assertCookieExpired(StandaloneHandoff::COOKIE);

    foreach ([$missing, $tampered, $wrongPurpose, $expired, $terminal] as $refusal) {
        expect($refusal->getStatusCode())->toBe(404)
            ->and((string) $refusal->getContent())->toBe('');
    }
});

it('validates invitation state and carries only a bounded intended destination', function (): void {
    $token = 'handoff-invitation-'.bin2hex(random_bytes(32));
    $invitation = createInvitationHandoff($token);
    $response = $this->get(route('bfc.invitations.accept', [
        'token' => $token,
        'intended' => '/test-created-destination',
    ], false));
    $response->assertRedirect(route('bfc.invitations.accept.form'))
        ->assertHeader('Referrer-Policy', 'no-referrer');
    $wireCookie = $response->getCookie(StandaloneHandoff::COOKIE, false);
    expect($wireCookie)->toBeInstanceOf(Cookie::class)
        ->and($wireCookie->getValue())->not->toContain($token)
        ->and($wireCookie->getPath())->toBe('/bfc/invitations/accept')
        ->and($wireCookie->isHttpOnly())->toBeTrue()
        ->and(strtolower((string) $wireCookie->getSameSite()))->toBe('lax');
    $inner = $response->getCookie(StandaloneHandoff::COOKIE)?->getValue();
    expect($inner)->toBeString();
    $this->withCookie(StandaloneHandoff::COOKIE, $inner);

    $form = $this->get('/bfc/invitations/accept');
    $form->assertOk()
        ->assertSee($invitation->email)
        ->assertSeeHtml('name="token" value="'.$token.'"')
        ->assertSeeHtml('name="intended" value="/test-created-destination"');
    expect(substr_count((string) $form->getContent(), $token))->toBe(1);

    $accepted = $this->post('/bfc/invitations/accept', [
        'token' => $token,
        'name' => 'Handoff Invitee',
        'password' => 'handoff invitee password',
        'password_confirmation' => 'handoff invitee password',
        'intended' => '/test-created-destination',
    ]);
    $accepted->assertRedirect('/test-created-destination')->assertCookieExpired(StandaloneHandoff::COOKIE);
    $expired = $accepted->getCookie(StandaloneHandoff::COOKIE, false);
    expect($expired)->toBeInstanceOf(Cookie::class)
        ->and($expired->getPath())->toBe('/bfc/invitations/accept')
        ->and($expired->isHttpOnly())->toBeTrue()
        ->and(strtolower((string) $expired->getSameSite()))->toBe('lax');
});

it('rejects invitation handoffs without a live expiry', function (string $state): void {
    $token = 'terminal-invitation-'.bin2hex(random_bytes(32));
    $attributes = [
        'email' => 'terminal-handoff-'.$state.'@example.test',
        'token' => Invitation::hashToken($token),
        'role' => UserRole::Member->value,
        'expires_at' => $state === 'expired' ? now()->subMinute() : now()->addHour(),
    ];

    if ($state === 'accepted') {
        $attributes['expires_at'] = now()->addHour();
        $attributes['accepted_at'] = now();
    }

    Invitation::factory()->create($attributes);

    $this->get(route('bfc.invitations.accept', ['token' => $token], false))
        ->assertNotFound()
        ->assertCookieExpired(StandaloneHandoff::COOKIE);
})->with([
    'expired' => 'expired',
    'accepted' => 'accepted',
]);

it('clears terminal JSON handoffs before returning validation errors', function (string $purpose): void {
    $token = 'terminal-json-'.bin2hex(random_bytes(32));

    if ($purpose === StandaloneHandoff::PASSWORD_RESET) {
        createResetHandoff($token, handoffResetUser('terminal-json-reset@example.test'));
        $bearerRoute = 'bfc.password.reset';
        $postPath = '/bfc/reset-password';
        $input = [
            'token' => 'wrong-token',
            'email' => 'terminal-json-reset@example.test',
            'password' => 'terminal json password',
            'password_confirmation' => 'terminal json password',
        ];
    } else {
        createInvitationHandoff($token);
        $bearerRoute = 'bfc.invitations.accept';
        $postPath = '/bfc/invitations/accept';
        $input = [
            'token' => 'wrong-token',
            'name' => 'Terminal JSON Invitee',
            'password' => 'terminal json password',
            'password_confirmation' => 'terminal json password',
        ];
    }

    $handoff = $this->get(route($bearerRoute, ['token' => $token], false));
    $inner = $handoff->getCookie(StandaloneHandoff::COOKIE)?->getValue();
    expect($inner)->toBeString();
    $this->withCookie(StandaloneHandoff::COOKIE, $inner);

    $response = $this->postJson($postPath, $input);
    $response->assertUnprocessable()->assertCookieExpired(StandaloneHandoff::COOKIE);
    expect($response->getCookie(StandaloneHandoff::COOKIE, false)?->getPath())
        ->toBe(app(StandaloneHandoff::class)->path($purpose));
})->with([
    'password reset' => StandaloneHandoff::PASSWORD_RESET,
    'invitation' => StandaloneHandoff::INVITATION,
]);

it('throttles bearer handoffs by IP before another token lookup', function (): void {
    $token = 'throttled-handoff-'.bin2hex(random_bytes(32));
    createResetHandoff($token, handoffResetUser('throttled-handoff@example.test'));
    $lookups = 0;

    DB::listen(static function (QueryExecuted $query) use (&$lookups): void {
        if (str_starts_with(strtolower(ltrim($query->sql)), 'select')
            && str_contains(strtolower($query->sql), 'password_reset_tokens')) {
            $lookups++;
        }
    });

    for ($attempt = 0; $attempt < 10; $attempt++) {
        $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.80'])
            ->get(route('bfc.password.reset', ['token' => $token], false))
            ->assertRedirect(route('bfc.password.reset.form'));
    }

    expect($lookups)->toBe(10);
    $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.80'])
        ->get(route('bfc.password.reset', ['token' => $token], false))
        ->assertTooManyRequests();
    expect($lookups)->toBe(10);

    $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.81'])
        ->get(route('bfc.password.reset', ['token' => $token], false))
        ->assertRedirect(route('bfc.password.reset.form'));
    expect($lookups)->toBe(11);
});

it('clears an existing handoff on managed refusal without starting a session', function (): void {
    config()->set('session.driver', 'database');
    $token = 'managed-handoff-'.bin2hex(random_bytes(32));
    createResetHandoff($token);
    $handoff = $this->get(route('bfc.password.reset', ['token' => $token], false));
    $inner = $handoff->getCookie(StandaloneHandoff::COOKIE)?->getValue();
    expect($inner)->toBeString()
        ->and(DB::table('sessions')->count())->toBe(0);

    InstallationAuthority::change(InstallationAuthority::current(), AuthorityMode::Managed);
    $this->withCookie(StandaloneHandoff::COOKIE, $inner);
    $response = $this->get('/bfc/reset-password');
    $response->assertNotFound()->assertCookieExpired(StandaloneHandoff::COOKIE);
    expect(DB::table('sessions')->count())->toBe(0);
});
