<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\Database\Factories\CredentialFactory;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureStandaloneAuthority;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\Invitation;
use ArtisanBuild\BuiltForCloud\Notifications\HumanInvitationNotification;
use ArtisanBuild\BuiltForCloud\Notifications\StandalonePasswordResetNotification;
use ArtisanBuild\BuiltForCloud\StandaloneAccess;
use ArtisanBuild\BuiltForCloud\StandaloneHandoff;
use ArtisanBuild\BuiltForCloud\Tests\TestCase;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;
use Symfony\Component\HttpFoundation\Cookie;

uses(RefreshDatabase::class);

function standaloneUser(
    string $email,
    UserRole|string $role = UserRole::Member,
    string $status = 'active',
    ?string $password = 'correct horse battery staple',
): User {
    $user = User::query()->create([
        'name' => 'Lifecycle '.strstr($email, '@', true),
        'email' => $email,
        'password' => $password === null ? null : Hash::make($password),
    ]);
    $user->forceFill([
        'role' => $role instanceof UserRole ? $role->value : $role,
        'status' => $status,
        'email_verified_at' => now(),
        'original_contact_email' => $email,
    ])->save();

    return $user;
}

function notificationToken(object $notification): string
{
    $url = $notification->toMail(new AnonymousNotifiable)->actionUrl;
    $path = parse_url((string) $url, PHP_URL_PATH);

    return rawurldecode(basename(is_string($path) ? $path : ''));
}

function loginStandalone(TestCase $test, User $user, string $password = 'correct horse battery staple'): void
{
    $test->withServerVariables([
        'REMOTE_ADDR' => '198.51.200.'.(((int) $user->getKey() % 250) + 1),
    ])->post('/bfc/login', [
        'email' => $user->email,
        'password' => $password,
    ])->assertRedirect('/');
}

function beginStandaloneHandoff(TestCase $test, string $routeName, string $token): TestResponse
{
    $cleanRoute = $routeName === 'bfc.password.reset'
        ? 'bfc.password.reset.form'
        : 'bfc.invitations.accept.form';
    $response = $test->get(route($routeName, ['token' => $token], false));
    $response->assertRedirect(route($cleanRoute));
    $cookie = $response->getCookie(StandaloneHandoff::COOKIE);
    expect($cookie)->toBeInstanceOf(Cookie::class);
    $test->withCookie(StandaloneHandoff::COOKIE, $cookie->getValue());

    return $test->get(route($cleanRoute, absolute: false))->assertOk();
}

it('mounts every named standalone route and renders package structural hooks', function (): void {
    $expected = [
        'bfc.login', 'bfc.login.store', 'bfc.logout',
        'bfc.password.request', 'bfc.password.email', 'bfc.password.reset', 'bfc.password.reset.form', 'bfc.password.update',
        'bfc.invitations.accept', 'bfc.invitations.accept.form', 'bfc.invitations.accept.store',
        'bfc.members.index', 'bfc.members.invitations.store', 'bfc.members.role.update', 'bfc.members.destroy',
        'bfc.sessions.index', 'bfc.sessions.destroy', 'bfc.sessions.destroy-others',
    ];

    foreach ($expected as $name) {
        expect(Route::has($name))->toBeTrue($name);
        expect(Route::getRoutes()->getByName($name)?->gatherMiddleware())
            ->toContain(EnsureStandaloneAuthority::class);
    }

    $this->get('/bfc/login')->assertOk()->assertSeeHtml('data-testid="login-form"');
    $this->get('/bfc/forgot-password')->assertOk()->assertSeeHtml('data-testid="password-request-form"');
    $resetUser = standaloneUser('person@example.test');
    DB::table('password_reset_tokens')->insert([
        'email' => $resetUser->email,
        'token' => hash('sha256', 'test-reset-token'),
        'created_at' => now(),
    ]);
    beginStandaloneHandoff($this, 'bfc.password.reset', 'test-reset-token')
        ->assertSeeHtml('data-testid="password-reset-form"')
        ->assertSee($resetUser->email);
    $invitation = Invitation::factory()->create([
        'email' => 'invitee@example.test',
        'token' => Invitation::hashToken('test-invitation-token'),
        'role' => UserRole::Member->value,
        'expires_at' => now()->addHour(),
    ]);
    beginStandaloneHandoff($this, 'bfc.invitations.accept', 'test-invitation-token')
        ->assertSeeHtml('data-testid="invitation-accept-form"')
        ->assertSee($invitation->email);

    $owner = standaloneUser('route-owner@example.test', UserRole::Owner);
    loginStandalone($this, $owner);
    $this->get('/bfc/members')
        ->assertOk()
        ->assertSeeHtml('data-testid="members-management"')
        ->assertSee($owner->email);
    $this->get('/bfc/me/sessions')
        ->assertOk()->assertSeeHtml('data-testid="sessions-management"');
});

it('authenticates only eligible canonical users with generic refusals and a local redirect', function (): void {
    $eligible = standaloneUser('eligible@example.test', UserRole::Admin);
    standaloneUser('null@example.test', UserRole::Member, password: null);
    $malformed = standaloneUser('malformed-hash@example.test');
    $malformed->forceFill(['password' => 'not-a-framework-hash'])->save();
    standaloneUser('inactive@example.test', UserRole::Member, status: 'inactive');
    standaloneUser('unknown-role@example.test', 'super-admin');

    foreach (['missing@example.test', 'null@example.test', 'malformed-hash@example.test', 'inactive@example.test', 'unknown-role@example.test'] as $index => $email) {
        $this->withServerVariables(['REMOTE_ADDR' => '198.51.201.'.($index + 1)])
            ->from('/bfc/login')->post('/bfc/login', [
                'email' => $email,
                'password' => 'wrong or unusable',
            ])->assertRedirect('/bfc/login')->assertSessionHasErrors(['email']);
    }

    $this->withServerVariables(['REMOTE_ADDR' => '198.51.201.99'])->post('/bfc/login', [
        'email' => $eligible->email,
        'password' => 'correct horse battery staple',
        'intended' => 'https://outside.example/path',
    ])->assertRedirect('/');

    $this->assertAuthenticatedAs($eligible);
    expect($eligible->refresh()->last_authenticated_at)->not->toBeNull()
        ->and(session(StandaloneAccess::SESSION_VERSION_KEY))->toBe($eligible->auth_session_version);
});

it('uses POST logout to end the current session', function (): void {
    $user = standaloneUser('logout@example.test');

    loginStandalone($this, $user);
    $this->post('/bfc/logout')->assertRedirect(route('bfc.login'));
    $this->assertGuest();
    $this->get('/bfc/members')->assertRedirect(route('bfc.login'));
});

it('invalidates previously unmarked sessions after password reset on a non-enumerable store', function (): void {
    $user = standaloneUser('unmarked-reset@example.test');
    $token = bin2hex(random_bytes(32));
    DB::table('password_reset_tokens')->insert([
        'email' => $user->email,
        'token' => hash('sha256', $token),
        'created_at' => now(),
    ]);

    Route::middleware('web')->get('/unmarked-reset-session', function () use ($user): string {
        Auth::guard('web')->login($user, false);
        request()->session()->regenerate();

        return 'unmarked-session';
    });
    $this->get('/unmarked-reset-session')->assertOk()->assertSee('unmarked-session');
    expect(Auth::check())->toBeTrue()
        ->and(session()->has(StandaloneAccess::SESSION_VERSION_KEY))->toBeFalse()
        ->and(config('session.driver'))->toBe('array');

    beginStandaloneHandoff($this, 'bfc.password.reset', $token);
    $this->post('/bfc/reset-password', [
        'token' => $token,
        'email' => $user->email,
        'password' => 'replacement secure password',
        'password_confirmation' => 'replacement secure password',
    ])->assertRedirect(route('bfc.login'));

    $this->get('/bfc/members')->assertRedirect(route('bfc.login'));
    $this->assertGuest();
});

it('invalidates marked stale sessions after password reset on a non-enumerable store', function (): void {
    $user = standaloneUser('marked-reset@example.test');
    $token = bin2hex(random_bytes(32));
    DB::table('password_reset_tokens')->insert([
        'email' => $user->email,
        'token' => hash('sha256', $token),
        'created_at' => now(),
    ]);

    loginStandalone($this, $user);
    beginStandaloneHandoff($this, 'bfc.password.reset', $token);
    $this->post('/bfc/reset-password', [
        'token' => $token,
        'email' => $user->email,
        'password' => 'replacement secure password',
        'password_confirmation' => 'replacement secure password',
    ])->assertRedirect(route('bfc.login'));

    $this->get('/bfc/members')->assertRedirect(route('bfc.login'));
    $this->assertGuest();
});

it('invalidates missing and stale local session markers on admin-only routes after password reset', function (bool $marked): void {
    Route::middleware(['web', 'bfc.admin'])->get('/reset-admin-only', static fn (): string => 'admin');
    $user = standaloneUser('reset-admin-'.($marked ? 'stale' : 'missing').'@example.test', UserRole::Admin);
    $token = bin2hex(random_bytes(32));
    $oldSessionVersion = $user->auth_session_version;
    DB::table('password_reset_tokens')->insert([
        'email' => $user->email,
        'token' => hash('sha256', $token),
        'created_at' => now(),
    ]);

    if ($marked) {
        loginStandalone($this, $user);
    } else {
        Route::middleware('web')->get('/reset-admin-unmarked-login', function () use ($user): string {
            Auth::guard('web')->login($user, false);
            request()->session()->regenerate();

            return 'unmarked-admin';
        });
        $this->get('/reset-admin-unmarked-login')->assertOk();
    }

    beginStandaloneHandoff($this, 'bfc.password.reset', $token);
    $this->post('/bfc/reset-password', [
        'token' => $token,
        'email' => $user->email,
        'password' => 'replacement secure password',
        'password_confirmation' => 'replacement secure password',
    ])->assertRedirect(route('bfc.login'));

    Auth::guard('web')->login($user->refresh(), false);
    $session = ['admin-session-residue' => 'present'];

    if ($marked) {
        $session[StandaloneAccess::SESSION_VERSION_KEY] = $oldSessionVersion;
    }

    $this->withSession($session)
        ->get('/reset-admin-only')
        ->assertForbidden()
        ->assertSessionMissing('admin-session-residue');
    $this->assertGuest();
})->with([false, true]);

it('fails closed without an exception for a package user behind a non-session guard', function (): void {
    Schema::table('users', static function (Blueprint $table): void {
        $table->string('api_token')->nullable();
    });
    $user = standaloneUser('token-guard@example.test');
    $user->forceFill(['api_token' => 'test-created-api-token'])->save();
    config([
        'auth.guards.token-probe' => [
            'driver' => 'token',
            'provider' => 'users',
            'input_key' => 'api_token',
            'storage_key' => 'api_token',
            'hash' => false,
        ],
    ]);
    Route::middleware(['auth:token-probe', 'bfc.auth'])
        ->get('/token-guarded', static fn (): string => 'protected');

    $this->getJson('/token-guarded?api_token=test-created-api-token')->assertUnauthorized();
});

it('bounds login independently by normalized address and IP', function (): void {
    $user = standaloneUser('throttled-login@example.test');

    foreach (range(1, 5) as $attempt) {
        $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.'.$attempt])
            ->post('/bfc/login', [
                'email' => $attempt % 2 === 0 ? ' THROTTLED-LOGIN@EXAMPLE.TEST ' : $user->email,
                'password' => 'wrong password',
            ])->assertRedirect();
    }

    $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.99'])
        ->post('/bfc/login', ['email' => $user->email, 'password' => 'correct horse battery staple'])
        ->assertTooManyRequests();
    $this->assertGuest();

    foreach (range(1, 5) as $attempt) {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])
            ->post('/bfc/login', [
                'email' => 'spray-'.$attempt.'@example.test',
                'password' => 'wrong password',
            ])->assertRedirect();
    }

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])
        ->post('/bfc/login', ['email' => 'spray-last@example.test', 'password' => 'wrong password'])
        ->assertTooManyRequests();
});

it('bounds reset independently by normalized address and IP without enumerating accounts', function (): void {
    Notification::fake();
    $user = standaloneUser('throttled-reset@example.test');

    foreach (range(1, 5) as $attempt) {
        $this->withServerVariables(['REMOTE_ADDR' => '192.0.2.'.$attempt])
            ->post('/bfc/forgot-password', [
                'email' => $attempt % 2 === 0 ? ' THROTTLED-RESET@EXAMPLE.TEST ' : $user->email,
            ])->assertRedirect()->assertSessionHas('status', 'recovery-requested');
    }

    $this->withServerVariables(['REMOTE_ADDR' => '192.0.2.99'])
        ->post('/bfc/forgot-password', ['email' => $user->email])
        ->assertTooManyRequests();

    foreach (range(1, 5) as $attempt) {
        $this->withServerVariables(['REMOTE_ADDR' => '198.18.0.1'])
            ->post('/bfc/forgot-password', ['email' => 'reset-spray-'.$attempt.'@example.test'])
            ->assertRedirect()->assertSessionHas('status', 'recovery-requested');
    }

    $this->withServerVariables(['REMOTE_ADDR' => '198.18.0.1'])
        ->post('/bfc/forgot-password', ['email' => 'reset-spray-last@example.test'])
        ->assertTooManyRequests();

    $comparisonUser = standaloneUser('enumeration-reset@example.test');
    $known = $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.40'])
        ->post('/bfc/forgot-password', ['email' => $comparisonUser->email]);
    $missing = $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.41'])
        ->post('/bfc/forgot-password', ['email' => 'missing@example.test']);
    expect($known->getStatusCode())->toBe($missing->getStatusCode());
    $known->assertSessionHas('status', 'recovery-requested');
    $missing->assertSessionHas('status', 'recovery-requested');
});

it('bounds invitation mail independently by actor address and IP', function (): void {
    Notification::fake();
    $owner = standaloneUser('throttled-invite-owner@example.test', UserRole::Owner);
    loginStandalone($this, $owner);

    foreach (range(1, 5) as $attempt) {
        $this->withServerVariables(['REMOTE_ADDR' => '198.51.101.'.$attempt])
            ->post('/bfc/members/invitations', [
                'email' => 'actor-invite-'.$attempt.'@example.test',
                'role' => 'member',
            ])->assertRedirect();
    }
    $this->withServerVariables(['REMOTE_ADDR' => '198.51.101.99'])
        ->post('/bfc/members/invitations', ['email' => 'actor-invite-last@example.test', 'role' => 'member'])
        ->assertTooManyRequests();

    $admins = collect(range(1, 11))->map(fn (int $attempt): User => standaloneUser(
        'throttled-invite-admin-'.$attempt.'@example.test',
        UserRole::Admin,
    ));

    foreach ($admins->take(5) as $index => $admin) {
        loginStandalone($this, $admin);
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.114.'.($index + 1)])
            ->post('/bfc/members/invitations', ['email' => 'same-address@example.test', 'role' => 'member']);
    }
    $addressActor = $admins->get(5);
    loginStandalone($this, $addressActor);
    $this->withServerVariables(['REMOTE_ADDR' => '203.0.114.99'])
        ->post('/bfc/members/invitations', ['email' => ' SAME-ADDRESS@EXAMPLE.TEST ', 'role' => 'member'])
        ->assertTooManyRequests();

    foreach ($admins->slice(6, 5) as $index => $admin) {
        loginStandalone($this, $admin);
        $this->withServerVariables(['REMOTE_ADDR' => '192.0.3.10'])
            ->post('/bfc/members/invitations', [
                'email' => 'ip-invite-'.$index.'@example.test',
                'role' => 'member',
            ])->assertRedirect();
    }
    $lastAdmin = standaloneUser('throttled-invite-admin-last@example.test', UserRole::Admin);
    loginStandalone($this, $lastAdmin);
    $this->withServerVariables(['REMOTE_ADDR' => '192.0.3.10'])
        ->post('/bfc/members/invitations', ['email' => 'ip-invite-last@example.test', 'role' => 'member'])
        ->assertTooManyRequests();
});

it('bounds password-confirmed session revocations by user session and IP', function (): void {
    $users = collect(range(1, 9))->map(fn (int $attempt): User => standaloneUser(
        'session-throttle-'.$attempt.'@example.test',
    ));
    Route::middleware('web')->get('/session-throttle-login/{user}', static function (string $user): string {
        $account = User::query()->findOrFail($user);
        Auth::guard('web')->login($account, false);
        request()->session()->regenerate();
        request()->session()->put(StandaloneAccess::SESSION_VERSION_KEY, $account->auth_session_version);

        return $account->email;
    });
    $useSessionCookie = function ($response): Cookie {
        $cookie = collect($response->headers->getCookies())->first(
            static fn (Cookie $candidate): bool => $candidate->getName() === config('session.cookie'),
        );
        expect($cookie)->toBeInstanceOf(Cookie::class);
        $this->withUnencryptedCookie($cookie->getName(), $cookie->getValue());

        return $cookie;
    };

    $sessionUser = $users->first();
    $loginResponse = $this->get('/session-throttle-login/'.$sessionUser->getKey());
    $loginResponse->assertOk()->assertSee($sessionUser->email);
    $sessionCookie = $useSessionCookie($loginResponse);
    foreach (range(1, 2) as $attempt) {
        $this->withUnencryptedCookie($sessionCookie->getName(), $sessionCookie->getValue())
            ->withServerVariables(['REMOTE_ADDR' => '198.51.102.1'])
            ->delete('/bfc/me/sessions/not-owned', ['password' => 'wrong password'])
            ->assertRedirect();
    }
    $this->withUnencryptedCookie($sessionCookie->getName(), $sessionCookie->getValue())
        ->withServerVariables(['REMOTE_ADDR' => '198.51.102.1'])
        ->delete('/bfc/me/sessions/others', ['password' => 'wrong password'])
        ->assertTooManyRequests();

    $userBucket = $users->get(1);
    foreach (range(1, 4) as $attempt) {
        $loginResponse = $this->get('/session-throttle-login/'.$userBucket->getKey());
        $loginResponse->assertOk();
        $useSessionCookie($loginResponse);
        $this->withServerVariables(['REMOTE_ADDR' => '198.51.103.'.$attempt])
            ->delete('/bfc/me/sessions/not-owned', ['password' => 'wrong password'])
            ->assertRedirect();
    }
    $loginResponse = $this->get('/session-throttle-login/'.$userBucket->getKey());
    $loginResponse->assertOk();
    $useSessionCookie($loginResponse);
    $this->withServerVariables(['REMOTE_ADDR' => '198.51.103.99'])
        ->delete('/bfc/me/sessions/not-owned', ['password' => 'wrong password'])
        ->assertTooManyRequests();

    foreach ($users->slice(2, 6) as $ipUser) {
        $loginResponse = $this->get('/session-throttle-login/'.$ipUser->getKey());
        $loginResponse->assertOk();
        $useSessionCookie($loginResponse);
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.115.10'])
            ->delete('/bfc/me/sessions/not-owned', ['password' => 'wrong password'])
            ->assertRedirect();
    }
    $lastIpUser = $users->last();
    $loginResponse = $this->get('/session-throttle-login/'.$lastIpUser->getKey());
    $loginResponse->assertOk();
    $useSessionCookie($loginResponse);
    $this->withServerVariables(['REMOTE_ADDR' => '203.0.115.10'])
        ->delete('/bfc/me/sessions/not-owned', ['password' => 'wrong password'])
        ->assertTooManyRequests();

    foreach (['bfc.sessions.destroy', 'bfc.sessions.destroy-others'] as $name) {
        expect(Route::getRoutes()->getByName($name)?->gatherMiddleware())
            ->toContain('throttle:bfc-session-confirm');
    }
});

it('keeps password requests non-enumerating and resets only eligible local accounts', function (): void {
    Notification::fake();
    $eligible = standaloneUser('recover@example.test');
    standaloneUser('generated@example.test')->forceFill(['email_is_generated' => true])->save();
    $responses = [];

    foreach (['recover@example.test', 'missing@example.test', 'generated@example.test'] as $email) {
        $responses[] = $this->from('/bfc/forgot-password')->post('/bfc/forgot-password', ['email' => $email]);
    }

    foreach ($responses as $response) {
        $response->assertRedirect('/bfc/forgot-password')->assertSessionHas('status', 'recovery-requested');
    }

    Notification::assertSentOnDemand(StandalonePasswordResetNotification::class, 1);
    $token = '';
    Notification::assertSentOnDemand(
        StandalonePasswordResetNotification::class,
        function (StandalonePasswordResetNotification $notification) use (&$token): bool {
            $token = notificationToken($notification);

            return true;
        },
    );

    expect($token)->not->toBe('')
        ->and(DB::table('password_reset_tokens')->where('email', $eligible->email)->value('token'))
        ->toBe(hash('sha256', $token));

    DB::table('sessions')->insert([
        'id' => 'recover-existing-session',
        'user_id' => $eligible->getKey(),
        'payload' => 'test',
        'last_activity' => now()->timestamp,
    ]);
    $role = $eligible->role;
    $status = $eligible->status;
    $original = $eligible->original_contact_email;

    beginStandaloneHandoff($this, 'bfc.password.reset', $token);
    $this->post('/bfc/reset-password', [
        'token' => $token,
        'email' => $eligible->email,
        'password' => 'new correct horse battery',
        'password_confirmation' => 'new correct horse battery',
        'role' => UserRole::Owner->value,
        'status' => 'active',
    ])->assertRedirect(route('bfc.login'));

    $eligible->refresh();
    expect(Hash::check('new correct horse battery', (string) $eligible->password))->toBeTrue()
        ->and($eligible->role)->toBe($role)
        ->and($eligible->status)->toBe($status)
        ->and($eligible->original_contact_email)->toBe($original)
        ->and(DB::table('password_reset_tokens')->where('email', $eligible->email)->exists())->toBeFalse()
        ->and(DB::table('sessions')->where('user_id', $eligible->getKey())->exists())->toBeFalse();

    $this->post('/bfc/reset-password', [
        'token' => $token,
        'email' => $eligible->email,
        'password' => 'another secure password',
        'password_confirmation' => 'another secure password',
    ])->assertSessionHasErrors(['email']);
});

it('replaces an earlier reset secret and never mails an ineligible address', function (): void {
    Notification::fake();
    $eligible = standaloneUser('latest-reset@example.test');
    $ineligible = standaloneUser('unverified-reset@example.test');
    $ineligible->forceFill(['email_verified_at' => null])->save();
    $passwordless = standaloneUser('passwordless-reset@example.test', password: null);

    $this->post('/bfc/forgot-password', ['email' => $eligible->email]);
    $firstHash = DB::table('password_reset_tokens')->where('email', $eligible->email)->value('token');
    $this->post('/bfc/forgot-password', ['email' => $eligible->email]);
    $secondHash = DB::table('password_reset_tokens')->where('email', $eligible->email)->value('token');
    $this->post('/bfc/forgot-password', ['email' => $ineligible->email]);
    $this->post('/bfc/forgot-password', ['email' => $passwordless->email]);

    expect($firstHash)->not->toBe($secondHash)
        ->and(DB::table('password_reset_tokens')->where('email', $eligible->email)->count())->toBe(1)
        ->and(DB::table('password_reset_tokens')->where('email', $ineligible->email)->exists())->toBeFalse()
        ->and(DB::table('password_reset_tokens')->where('email', $passwordless->email)->exists())->toBeTrue();
    Notification::assertSentOnDemand(StandalonePasswordResetNotification::class, 3);
});

it('enforces addressed invitation roles and accepts once with server-owned identity fields', function (): void {
    Notification::fake();
    $owner = standaloneUser('invite-owner@example.test', UserRole::Owner);
    $admin = standaloneUser('invite-admin@example.test', UserRole::Admin);
    $member = standaloneUser('invite-member@example.test');

    loginStandalone($this, $admin);
    $this->post('/bfc/members/invitations', [
        'email' => 'new-admin@example.test',
        'role' => 'admin',
    ])->assertForbidden();
    loginStandalone($this, $member);
    $this->post('/bfc/members/invitations', [
        'email' => 'new-member@example.test',
        'role' => 'member',
    ])->assertForbidden();

    loginStandalone($this, $owner);
    $this->post('/bfc/members/invitations', [
        'email' => '  New-Admin@Example.Test ',
        'role' => 'admin',
    ])->assertRedirect();

    $this->post('/bfc/members/invitations', [
        'email' => 'new-admin@example.test',
        'role' => 'admin',
    ])->assertStatus(422);

    $stored = Invitation::query()->sole();
    expect($stored->email)->toBe('new-admin@example.test')
        ->and($stored->role)->toBe(UserRole::Admin->value)
        ->and($stored->token)->toMatch('/^[a-f0-9]{64}$/')
        ->and($stored->expires_at)->not->toBeNull();

    $token = '';
    Notification::assertSentOnDemand(
        HumanInvitationNotification::class,
        function (HumanInvitationNotification $notification) use (&$token): bool {
            $token = notificationToken($notification);

            return true;
        },
    );
    expect($stored->token)->toBe(hash('sha256', $token));

    $this->post('/bfc/logout')->assertRedirect(route('bfc.login'));
    beginStandaloneHandoff($this, 'bfc.invitations.accept', $token);
    $this->post('/bfc/invitations/accept', [
        'token' => $token,
        'name' => 'Invited Administrator',
        'password' => 'invitation secure password',
        'password_confirmation' => 'invitation secure password',
        'role' => UserRole::Owner->value,
        'email' => 'attacker@example.test',
        'status' => 'inactive',
        'intended' => '//outside.example',
    ])->assertRedirect('/');

    $created = User::query()->where('email', 'new-admin@example.test')->sole();
    expect($created->role)->toBe(UserRole::Admin->value)
        ->and($created->status)->toBe('active')
        ->and($created->email_verified_at)->not->toBeNull()
        ->and($created->scalpels_id)->toBeNull()
        ->and($stored->refresh()->used_by)->toBe((string) $created->getKey());
    $this->assertAuthenticatedAs($created);
    $this->get('/bfc/members')->assertOk()->assertSee($created->email);

    $this->post('/bfc/logout')->assertRedirect(route('bfc.login'));
    $this->post('/bfc/invitations/accept', [
        'token' => $token,
        'name' => 'Replay',
        'password' => 'invitation secure password',
        'password_confirmation' => 'invitation secure password',
    ])->assertSessionHasErrors(['token']);
    expect(User::query()->where('email', 'new-admin@example.test')->count())->toBe(1);
});

it('applies membership boundaries and contains account-bound state on deactivation', function (): void {
    $owner = standaloneUser('manage-owner@example.test', UserRole::Owner);
    $admin = standaloneUser('manage-admin@example.test', UserRole::Admin);
    $member = standaloneUser('manage-member@example.test');
    $otherAdmin = standaloneUser('manage-other-admin@example.test', UserRole::Admin);

    loginStandalone($this, $admin);
    $this->put('/bfc/members/'.$member->getKey().'/role', ['role' => 'admin'])
        ->assertForbidden();
    $this->delete('/bfc/members/'.$otherAdmin->getKey())->assertForbidden();
    loginStandalone($this, $owner);
    $this->put('/bfc/members/'.$member->getKey().'/role', ['role' => 'admin'])
        ->assertRedirect();
    expect($member->refresh()->role)->toBe(UserRole::Admin->value);
    $this->put('/bfc/members/'.$member->getKey().'/role', ['role' => 'member'])
        ->assertRedirect();

    CredentialFactory::new()->forUser((string) $member->getKey())->create();
    $installationCredential = CredentialFactory::new()->create();
    DB::table('password_reset_tokens')->insert([
        'email' => $member->email,
        'token' => hash('sha256', 'member-reset'),
        'created_at' => now(),
    ]);
    DB::table('sessions')->insert([
        'id' => 'member-session',
        'user_id' => $member->getKey(),
        'payload' => 'test',
        'last_activity' => now()->timestamp,
    ]);

    loginStandalone($this, $admin);
    $this->delete('/bfc/members/'.$member->getKey())->assertRedirect();
    expect($member->refresh()->status)->toBe('inactive')
        ->and($member->deactivated_at)->not->toBeNull()
        ->and(Credential::query()->where('user_id', $member->getKey())->whereNull('revoked_at')->exists())->toBeFalse()
        ->and($installationCredential->refresh()->revoked_at)->toBeNull()
        ->and(DB::table('password_reset_tokens')->where('email', $member->email)->exists())->toBeFalse()
        ->and(DB::table('sessions')->where('user_id', $member->getKey())->exists())->toBeFalse()
        ->and(User::query()->whereKey($member->getKey())->exists())->toBeTrue();

    loginStandalone($this, $owner);
    $this->delete('/bfc/members/'.$owner->getKey())->assertForbidden();
});

it('refuses every local route in managed mode before writes or mail', function (): void {
    Notification::fake();
    $owner = standaloneUser('managed-owner@example.test', UserRole::Owner);
    InstallationAuthority::change(InstallationAuthority::current(), AuthorityMode::Managed);

    $this->get('/bfc/login')->assertNotFound();
    $this->post('/bfc/login', ['email' => $owner->email, 'password' => 'correct horse battery staple'])->assertNotFound();
    $this->post('/bfc/forgot-password', ['email' => $owner->email])->assertNotFound();
    $this->get('/bfc/reset-password/token?email='.$owner->email)->assertNotFound();
    $this->post('/bfc/reset-password', [])->assertNotFound();
    $this->get('/bfc/invitations/token')->assertNotFound();
    $this->post('/bfc/invitations/accept', [])->assertNotFound();
    $this->actingAs($owner)->get('/bfc/members')->assertNotFound();
    $this->actingAs($owner)->post('/bfc/members/invitations', [
        'email' => 'blocked@example.test', 'role' => 'member',
    ])->assertNotFound();
    $this->actingAs($owner)->get('/bfc/me/sessions')->assertNotFound();
    $this->actingAs($owner)->delete('/bfc/me/sessions/others', ['password' => 'correct horse battery staple'])->assertNotFound();
    $this->actingAs($owner)->delete('/bfc/me/sessions/other', ['password' => 'correct horse battery staple'])->assertNotFound();
    $this->actingAs($owner)->put('/bfc/members/'.$owner->getKey().'/role', ['role' => 'member'])->assertNotFound();
    $this->actingAs($owner)->delete('/bfc/members/'.$owner->getKey())->assertNotFound();
    $this->actingAs($owner)->post('/bfc/logout')->assertNotFound();

    expect(Invitation::query()->count())->toBe(0)
        ->and(DB::table('password_reset_tokens')->count())->toBe(0);
    Notification::assertNothingSent();
});

it('creates and safely rolls back package reset and session schema', function (): void {
    expect(Schema::hasTable('password_reset_tokens'))->toBeTrue()
        ->and(Schema::hasTable('sessions'))->toBeTrue();

    $migration = require __DIR__.'/../database/migrations/0001_01_01_000003_create_password_reset_tokens_and_sessions_tables.php';
    $migration->down();

    expect(Schema::hasTable('password_reset_tokens'))->toBeFalse()
        ->and(Schema::hasTable('sessions'))->toBeFalse();
});
