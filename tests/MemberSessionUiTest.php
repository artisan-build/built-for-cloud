<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\Http\Controllers\UiHome;
use ArtisanBuild\BuiltForCloud\Http\Controllers\UiLogout;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUiAuthority;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAuthenticated;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\Invitation;
use ArtisanBuild\BuiltForCloud\StandaloneRouteOwnership;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Routing\Route as RoutingRoute;
use Illuminate\Routing\Router;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\DataProvider;

final class MemberSessionUiTest extends TestCase
{
    use RefreshDatabase;

    /** @param Application $app */
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('built-for-cloud.manifest', [
            'name' => 'Test-created member and session application',
            'slug' => 'test-created-member-session-application',
            'description' => 'Test-created member and session description',
            'icon' => 'https://assets.example.test/test-created-member-session.svg',
            'product_url' => 'https://scalpels.app/products/test-created-member-session',
        ]);
        $app['config']->set('built-for-cloud.managed.client_secret', str_repeat('a', 64));
    }

    /** @return iterable<string, array{UserRole, bool}> */
    public static function roleFlagProvider(): iterable
    {
        foreach (UserRole::cases() as $role) {
            foreach ([true, false] as $enabled) {
                yield $role->value.'-'.($enabled ? 'on' : 'off') => [$role, $enabled];
            }
        }
    }

    /** @return iterable<string, array{AuthorityMode, UserRole, bool}> */
    public static function managedRoleFlagProvider(): iterable
    {
        foreach (UserRole::cases() as $role) {
            foreach ([true, false] as $enabled) {
                yield $role->value.'-'.($enabled ? 'on' : 'off') => [AuthorityMode::Managed, $role, $enabled];
            }
        }
    }

    /** @return iterable<string, array{AuthorityMode, UserRole, string}> */
    public static function logoutProvider(): iterable
    {
        foreach (AuthorityMode::cases() as $mode) {
            foreach (UserRole::cases() as $role) {
                foreach (['valid', 'missing', 'invalid'] as $token) {
                    yield $mode->value.'-'.$role->value.'-'.$token => [$mode, $role, $token];
                }
            }
        }
    }

    public function test_ui_route_registry_and_page_wiring_are_exact_and_flag_independent(): void
    {
        config([
            'built-for-cloud.ui.member_management' => false,
            'built-for-cloud.ui.session_management' => false,
        ]);

        $routes = collect(Route::getRoutes()->getRoutes())
            ->filter(static fn (RoutingRoute $route): bool => str_starts_with((string) $route->getName(), 'bfc.ui.'))
            ->values();

        $this->assertSame([
            ['bfc.ui.home', 'GET', 'bfc/ui', UiHome::class],
            ['bfc.ui.logout', 'POST', 'bfc/ui/logout', UiLogout::class],
        ], $routes->map(static fn (RoutingRoute $route): array => [
            $route->getName(),
            $route->methods()[0],
            $route->uri(),
            $route->getActionName(),
        ])->all());

        /** @var Router $router */
        $router = app('router');
        StandaloneRouteOwnership::assertOwned($router, $routes->all());
        $inventory = StandaloneRouteOwnership::packageMiddlewareInventory($routes->all());
        StandaloneRouteOwnership::assertPackageMiddlewareOwned($router, $inventory);

        foreach ($routes as $route) {
            $middleware = $router->gatherRouteMiddleware($route);
            $this->assertContains(StartSession::class, $middleware);
            $this->assertContains(PreventRequestForgery::class, $middleware);
            $this->assertContains(EnsureUiAuthority::class, $middleware);
            $this->assertContains(EnsureUserIsAuthenticated::class, $middleware);
        }

        $response = $this->actingAsVersioned($this->user(UserRole::Owner))->get('/bfc/ui');
        $response->assertOk()
            ->assertSeeHtml('data-testid="ui-logout-form"')
            ->assertSee('action="'.route('bfc.ui.logout').'"', false)
            ->assertDontSeeHtml('data-testid="ui-nav-member-management"')
            ->assertDontSeeHtml('data-testid="ui-nav-session-management"');
    }

    #[DataProvider('roleFlagProvider')]
    public function test_standalone_member_ui_and_actions_keep_the_role_matrix_with_the_flag_on_or_off(
        UserRole $role,
        bool $enabled,
    ): void {
        Notification::fake();
        config(['built-for-cloud.ui.member_management' => $enabled]);
        $actor = $this->user($role, password: 'test-created-member-password');
        $targetMember = $this->user(UserRole::Member);
        $targetAdmin = $this->user(UserRole::Admin);

        $home = $this->actingAsVersioned($actor)->get('/bfc/ui')->assertOk();
        $this->assertMarker(
            (string) $home->getContent(),
            'ui-nav-member-management',
            $enabled && $role !== UserRole::Member,
        );
        if ($enabled && $role !== UserRole::Member) {
            $home->assertSee('href="'.route('bfc.members.index').'"', false);
        }

        $page = $this->actingAsVersioned($actor)->get('/bfc/members')->assertOk();
        $content = (string) $page->getContent();
        $this->assertMarker($content, 'members-invitation-form', $role !== UserRole::Member);
        $this->assertSame($role === UserRole::Owner ? 2 : 0, substr_count($content, 'data-testid="members-role-form"'));
        $this->assertSame(match ($role) {
            UserRole::Owner => 2,
            UserRole::Admin => 1,
            UserRole::Member => 0,
        }, substr_count($content, 'data-testid="members-deactivation-form"'));

        $inviteRole = $role === UserRole::Owner ? UserRole::Admin : UserRole::Member;
        $inviteEmail = 'test-created-'.$role->value.'-invite@example.test';
        $invite = $this->actingAsVersioned($actor)->post('/bfc/members/invitations', [
            'email' => $inviteEmail,
            'role' => $inviteRole->value,
        ]);
        if ($role === UserRole::Member) {
            $invite->assertForbidden();
            $this->assertFalse(Invitation::query()->where('email', $inviteEmail)->exists());
        } else {
            $invite->assertRedirect();
            $this->assertTrue(Invitation::query()
                ->where('email', $inviteEmail)
                ->where('role', $inviteRole->value)
                ->exists());
        }

        $roleChange = $this->actingAsVersioned($actor)->put('/bfc/members/'.$targetMember->getKey().'/role', [
            'role' => UserRole::Admin->value,
        ]);
        if ($role === UserRole::Owner) {
            $roleChange->assertRedirect();
            $this->assertSame(UserRole::Admin, $targetMember->refresh()->roleValue());
        } else {
            $roleChange->assertForbidden();
            $this->assertSame(UserRole::Member, $targetMember->refresh()->roleValue());
        }

        $deactivationTarget = $role === UserRole::Owner ? $targetAdmin : $targetMember;
        $deactivate = $this->actingAsVersioned($actor)->delete('/bfc/members/'.$deactivationTarget->getKey());
        if ($role === UserRole::Member) {
            $deactivate->assertForbidden();
            $this->assertSame('active', $deactivationTarget->refresh()->status);
        } else {
            $deactivate->assertRedirect();
            $this->assertSame('inactive', $deactivationTarget->refresh()->status);
        }

        if ($role === UserRole::Admin) {
            $blockedInvite = 'test-created-admin-blocked@example.test';
            $this->actingAsVersioned($actor)->post('/bfc/members/invitations', [
                'email' => $blockedInvite,
                'role' => UserRole::Admin->value,
            ])->assertForbidden();
            $this->actingAsVersioned($actor)->delete('/bfc/members/'.$targetAdmin->getKey())->assertForbidden();
            $this->assertFalse(Invitation::query()->where('email', $blockedInvite)->exists());
            $this->assertSame('active', $targetAdmin->refresh()->status);
        }
    }

    #[DataProvider('roleFlagProvider')]
    public function test_standalone_session_ui_and_password_confirmed_verbs_work_with_the_flag_on_or_off(
        UserRole $role,
        bool $enabled,
    ): void {
        config([
            'built-for-cloud.ui.session_management' => $enabled,
            'session.driver' => 'database',
        ]);
        $actor = $this->user($role, password: 'test-created-session-password');
        $this->seedSession($actor, 'test-created-session-one');
        $this->seedSession($actor, 'test-created-session-two');

        $home = $this->actingAsVersioned($actor)->get('/bfc/ui')->assertOk();
        $this->assertMarker((string) $home->getContent(), 'ui-nav-session-management', $enabled);
        if ($enabled) {
            $home->assertSee('href="'.route('bfc.sessions.index').'"', false);
        }

        $page = $this->actingAsVersioned($actor)->get('/bfc/me/sessions')->assertOk();
        $this->assertGreaterThanOrEqual(2, substr_count((string) $page->getContent(), 'data-testid="sessions-revoke-form"'));
        $page->assertSeeHtml('data-testid="sessions-revoke-others-form"')
            ->assertSee('test-created-session-one');

        $this->actingAsVersioned($actor)->delete('/bfc/me/sessions/test-created-session-one', [
            'password' => 'test-created-session-password',
        ])->assertRedirect();
        $this->assertDatabaseMissing('sessions', ['id' => 'test-created-session-one']);

        $this->actingAsVersioned($actor)->delete('/bfc/me/sessions/others', [
            'password' => 'test-created-session-password',
        ])->assertRedirect();
        $this->assertDatabaseMissing('sessions', ['id' => 'test-created-session-two']);
    }

    #[DataProvider('managedRoleFlagProvider')]
    public function test_managed_member_ui_is_an_incomplete_read_only_local_list_and_standalone_actions_still_refuse(
        AuthorityMode $mode,
        UserRole $role,
        bool $enabled,
    ): void {
        Notification::fake();
        $this->setAuthority($mode);
        config([
            'built-for-cloud.ui.member_management' => $enabled,
            'built-for-cloud.ui.session_management' => $enabled,
        ]);
        $actor = $this->user($role, managed: true);
        $known = $this->user(UserRole::Member, managed: true);
        $differentIssuer = $this->user(UserRole::Member, managed: true);
        $differentIssuer->forceFill(['scalpels_issuer' => 'https://different-issuer.example.test'])->save();
        $differentConnection = $this->user(UserRole::Member, managed: true);
        $differentConnection->forceFill(['scalpels_connection_id' => 'test-created-different-connection'])->save();
        $localOnly = $this->user(UserRole::Member);
        $this->seedSession($actor, 'test-created-managed-session');

        $home = $this->actingAsVersioned($actor)->get('/bfc/ui')->assertOk();
        $content = (string) $home->getContent();
        $showsMembers = $enabled && $role !== UserRole::Member;
        $this->assertMarker($content, 'ui-nav-member-management', $showsMembers);
        $this->assertMarker($content, 'managed-members-list', $showsMembers);
        $this->assertMarker($content, 'managed-members-incomplete', $showsMembers);
        $this->assertMarker($content, 'ui-nav-session-management', false);
        $this->assertStringNotContainsString('data-testid="members-invitation-form"', $content);
        $this->assertStringNotContainsString('data-testid="members-role-form"', $content);
        $this->assertStringNotContainsString('data-testid="members-deactivation-form"', $content);

        if ($showsMembers) {
            $home->assertSee('href="#managed-members"', false)
                ->assertSee($known->name)
                ->assertSee($known->email)
                ->assertDontSee($differentIssuer->email)
                ->assertDontSee($differentConnection->email)
                ->assertDontSee($localOnly->email);
        }

        $before = [
            'invitations' => Invitation::query()->count(),
            'known_role' => $known->role,
            'known_status' => $known->status,
            'sessions' => DB::table('sessions')->where('user_id', $actor->getKey())->count(),
        ];
        $blockedInvite = 'test-created-managed-blocked@example.test';
        $this->actingAsVersioned($actor)->post('/bfc/members/invitations', [
            'email' => $blockedInvite,
            'role' => UserRole::Member->value,
        ])->assertNotFound();
        $this->actingAsVersioned($actor)->put('/bfc/members/'.$known->getKey().'/role', [
            'role' => UserRole::Admin->value,
        ])->assertNotFound();
        $this->actingAsVersioned($actor)->delete('/bfc/members/'.$known->getKey())->assertNotFound();
        $this->actingAsVersioned($actor)->get('/bfc/me/sessions')->assertNotFound();
        $this->actingAsVersioned($actor)->delete('/bfc/me/sessions/others', [
            'password' => 'unused-managed-password',
        ])->assertNotFound();

        $this->assertSame($before, [
            'invitations' => Invitation::query()->count(),
            'known_role' => $known->refresh()->role,
            'known_status' => $known->status,
            'sessions' => DB::table('sessions')->where('user_id', $actor->getKey())->count(),
        ]);
        Notification::assertNothingSent();
    }

    #[DataProvider('logoutProvider')]
    public function test_ui_logout_is_mode_neutral_and_csrf_failures_leave_every_role_session_live(
        AuthorityMode $mode,
        UserRole $role,
        string $tokenState,
    ): void {
        $this->setAuthority($mode);
        $user = $this->user($role, managed: $mode === AuthorityMode::Managed);
        $csrf = 'test-created-csrf-token';
        $session = [
            '_token' => $csrf,
            'logout-proof' => 'test-created-live-session',
        ];
        $payload = match ($tokenState) {
            'valid' => ['_token' => $csrf],
            'invalid' => ['_token' => 'test-created-invalid-token'],
            default => [],
        };

        $this->actingAsVersioned($user)->withSession($session);
        app()->instance('env', 'local');
        $response = $this->post('/bfc/ui/logout', $payload);

        if ($tokenState === 'valid') {
            $response->assertRedirect('/')
                ->assertSessionMissing('logout-proof')
                ->assertSessionHas('_token', static fn (mixed $token): bool => is_string($token)
                    && $token !== ''
                    && $token !== $csrf);
            $this->assertGuest();
            $login = $mode === AuthorityMode::Managed ? 'bfc.managed.login' : 'bfc.login';
            $this->get('/bfc/ui')->assertRedirect(route($login, ['intended' => '/bfc/ui']));

            return;
        }

        $response->assertStatus(419)->assertSessionHas('logout-proof', 'test-created-live-session');
        $this->assertAuthenticatedAs($user);
        $this->get('/bfc/ui')->assertOk()->assertSeeHtml('data-testid="ui-shell"');
    }

    private function setAuthority(AuthorityMode $mode): void
    {
        if ($mode === AuthorityMode::Standalone) {
            return;
        }

        DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
            'mode' => AuthorityMode::Managed->value,
            'generation' => 2,
            'issuer' => 'https://issuer.example.test',
            'connection_id' => 'test-created-ui-connection',
            'organization_id' => 'test-created-ui-organization',
            'installation_id' => 'test-created-ui-installation',
            'authority_base_url' => 'https://authority.example.test',
            'managed_connection_status' => 'active',
            'managed_connection_generation' => 2,
            'managed_connection_roster_version' => 3,
            'managed_connection_response_sequence' => 4,
        ]);
    }

    private function user(UserRole $role, ?string $password = null, bool $managed = false): User
    {
        $suffix = bin2hex(random_bytes(5));
        $email = 'test-created-'.$role->value.'-'.$suffix.'@example.test';
        $user = User::query()->create([
            'name' => 'Test-created '.$role->value.' '.$suffix,
            'email' => $email,
            'password' => Hash::make($password ?? 'test-created-default-password'),
        ]);
        $attributes = [
            'role' => $role->value,
            'status' => 'active',
            'email_verified_at' => now(),
            'original_contact_email' => $email,
        ];

        if ($managed) {
            $attributes += [
                'scalpels_issuer' => 'https://issuer.example.test',
                'scalpels_connection_id' => 'test-created-ui-connection',
                'scalpels_id' => 'test-created-subject-'.$suffix,
                'managed_membership_status' => 'active',
                'managed_membership_role' => $role->value,
                'managed_membership_generation' => 2,
                'managed_membership_roster_version' => 3,
                'managed_membership_response_sequence' => 4,
                'managed_membership_responded_at' => now()->toAtomString(),
                'membership_confirmed_at' => now(),
            ];
        }

        $user->forceFill($attributes)->save();

        return $user;
    }

    private function seedSession(User $user, string $id): void
    {
        DB::table('sessions')->insert([
            'id' => $id,
            'user_id' => $user->getKey(),
            'ip_address' => '192.0.2.10',
            'user_agent' => 'test-created-agent',
            'payload' => 'test-created-payload',
            'last_activity' => now()->timestamp,
        ]);
    }

    private function assertMarker(string $content, string $marker, bool $visible): void
    {
        $this->assertSame($visible ? 1 : 0, substr_count($content, 'data-testid="'.$marker.'"'), $marker);
    }
}
