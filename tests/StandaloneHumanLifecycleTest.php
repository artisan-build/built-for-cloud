<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\Database\Factories\CredentialFactory;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\Invitation;
use ArtisanBuild\BuiltForCloud\Notifications\HumanInvitationNotification;
use ArtisanBuild\BuiltForCloud\Notifications\StandalonePasswordResetNotification;
use ArtisanBuild\BuiltForCloud\StandaloneAccess;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;

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

it('mounts every named standalone route and renders package structural hooks', function (): void {
    $expected = [
        'bfc.login', 'bfc.login.store', 'bfc.logout',
        'bfc.password.request', 'bfc.password.email', 'bfc.password.reset', 'bfc.password.update',
        'bfc.invitations.accept', 'bfc.invitations.accept.store',
        'bfc.members.index', 'bfc.members.invitations.store', 'bfc.members.role.update', 'bfc.members.destroy',
        'bfc.sessions.index', 'bfc.sessions.destroy', 'bfc.sessions.destroy-others',
    ];

    foreach ($expected as $name) {
        expect(Route::has($name))->toBeTrue($name);
        expect(Route::getRoutes()->getByName($name)?->gatherMiddleware())
            ->toContain('bfc.standalone');
    }

    $this->get('/bfc/login')->assertOk()->assertSeeHtml('data-testid="login-form"');
    $this->get('/bfc/forgot-password')->assertOk()->assertSeeHtml('data-testid="password-request-form"');
    $this->get('/bfc/reset-password/test-token?email=person%40example.test')
        ->assertOk()->assertSeeHtml('data-testid="password-reset-form"');
    $this->get('/bfc/invitations/test-token?email=invitee%40example.test')
        ->assertOk()->assertSeeHtml('data-testid="invitation-accept-form"');

    $owner = standaloneUser('route-owner@example.test', UserRole::Owner);
    $this->actingAs($owner)->get('/bfc/members')
        ->assertOk()
        ->assertSeeHtml('data-testid="members-management"')
        ->assertSee($owner->email);
    $this->actingAs($owner)->get('/bfc/me/sessions')
        ->assertOk()->assertSeeHtml('data-testid="sessions-management"');
});

it('authenticates only eligible canonical users with generic refusals and a local redirect', function (): void {
    $eligible = standaloneUser('eligible@example.test', UserRole::Admin);
    standaloneUser('null@example.test', UserRole::Member, password: null);
    $malformed = standaloneUser('malformed-hash@example.test');
    $malformed->forceFill(['password' => 'not-a-framework-hash'])->save();
    standaloneUser('inactive@example.test', UserRole::Member, status: 'inactive');
    standaloneUser('unknown-role@example.test', 'super-admin');

    foreach (['missing@example.test', 'null@example.test', 'malformed-hash@example.test', 'inactive@example.test', 'unknown-role@example.test'] as $email) {
        $this->from('/bfc/login')->post('/bfc/login', [
            'email' => $email,
            'password' => 'wrong or unusable',
        ])->assertRedirect('/bfc/login')->assertSessionHasErrors(['email']);
    }

    $this->post('/bfc/login', [
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

    $this->actingAs($user)->post('/bfc/logout')->assertRedirect(route('bfc.login'));
    $this->assertGuest();
    $this->get('/bfc/members')->assertRedirect(route('bfc.login'));
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

    $this->actingAs($admin)->post('/bfc/members/invitations', [
        'email' => 'new-admin@example.test',
        'role' => 'admin',
    ])->assertForbidden();
    $this->actingAs($member)->post('/bfc/members/invitations', [
        'email' => 'new-member@example.test',
        'role' => 'member',
    ])->assertForbidden();

    $this->actingAs($owner)->post('/bfc/members/invitations', [
        'email' => '  New-Admin@Example.Test ',
        'role' => 'admin',
    ])->assertRedirect();

    $this->actingAs($owner)->post('/bfc/members/invitations', [
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

    Auth::logout();
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

    Auth::logout();
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

    $this->actingAs($admin)->put('/bfc/members/'.$member->getKey().'/role', ['role' => 'admin'])
        ->assertForbidden();
    $this->actingAs($admin)->delete('/bfc/members/'.$otherAdmin->getKey())->assertForbidden();
    $this->actingAs($owner)->put('/bfc/members/'.$member->getKey().'/role', ['role' => 'admin'])
        ->assertRedirect();
    expect($member->refresh()->role)->toBe(UserRole::Admin->value);
    $this->actingAs($owner)->put('/bfc/members/'.$member->getKey().'/role', ['role' => 'member'])
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

    $this->actingAs($admin)->delete('/bfc/members/'.$member->getKey())->assertRedirect();
    expect($member->refresh()->status)->toBe('inactive')
        ->and($member->deactivated_at)->not->toBeNull()
        ->and(Credential::query()->where('user_id', $member->getKey())->whereNull('revoked_at')->exists())->toBeFalse()
        ->and($installationCredential->refresh()->revoked_at)->toBeNull()
        ->and(DB::table('password_reset_tokens')->where('email', $member->email)->exists())->toBeFalse()
        ->and(DB::table('sessions')->where('user_id', $member->getKey())->exists())->toBeFalse()
        ->and(User::query()->whereKey($member->getKey())->exists())->toBeTrue();

    $this->actingAs($owner)->delete('/bfc/members/'.$owner->getKey())->assertForbidden();
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
