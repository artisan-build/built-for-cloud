<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUiAuthority;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAuthenticated;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\LandingManifest;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Routing\Route as RoutingRoute;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\View;
use PHPUnit\Framework\Attributes\DataProvider;
use RuntimeException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

final class AuthenticatedUiTest extends TestCase
{
    use RefreshDatabase;

    /** @param Application $app */
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);

        $app['config']->set('built-for-cloud.ui', [
            'landing_page' => true,
            'member_management' => true,
            'personal_credentials' => true,
            'installation_credentials' => true,
            'session_management' => true,
            'managed_transitions' => true,
            'credential_purposes' => [],
        ]);
        $app['config']->set('built-for-cloud.manifest', [
            'name' => 'Test <Shell> Application',
            'slug' => 'test-shell-application',
            'description' => 'A test-created <strong>shell</strong> description.',
            'icon' => 'https://assets.example.test/test-shell.svg?variant=ui&source=test',
            'product_url' => 'https://scalpels.app/products/test-shell-application?source=test&kind=ui',
        ]);
        $app['config']->set('built-for-cloud.managed.client_secret', str_repeat('a', 64));
    }

    /** @return iterable<string, array{AuthorityMode, UserRole}> */
    public static function roleModeProvider(): iterable
    {
        foreach (AuthorityMode::cases() as $mode) {
            foreach (UserRole::cases() as $role) {
                yield $mode->value.'-'.$role->value => [$mode, $role];
            }
        }
    }

    #[DataProvider('roleModeProvider')]
    public function test_every_human_role_sees_one_manifest_shell_and_only_its_enabled_navigation(
        AuthorityMode $mode,
        UserRole $role,
    ): void {
        $this->setAuthority($mode);
        $user = $this->user($role, managed: $mode === AuthorityMode::Managed);
        $layoutRenders = 0;
        View::composer('bfc::layout', static function () use (&$layoutRenders): void {
            $layoutRenders++;
        });

        $response = $this->actingAsVersioned($user)->get('/bfc/ui');

        $response->assertOk()
            ->assertSeeHtml('data-testid="ui-shell"')
            ->assertSeeHtml('data-testid="ui-manifest"')
            ->assertSeeHtml('data-app-slug="test-shell-application"')
            ->assertSeeHtml('data-testid="ui-navigation"');
        $content = (string) $response->getContent();
        $this->assertSame(1, $layoutRenders);
        $this->assertSame(1, substr_count($content, '<main>'));

        foreach ([
            'Test <Shell> Application',
            'A test-created <strong>shell</strong> description.',
            'https://assets.example.test/test-shell.svg?variant=ui&source=test',
            'https://scalpels.app/products/test-shell-application?source=test&kind=ui',
        ] as $value) {
            $response->assertSee($value)->assertDontSee($value, false);
        }

        $this->assertMarker($content, 'ui-nav-member-management', in_array($role, [UserRole::Owner, UserRole::Admin], true));
        $this->assertMarker($content, 'ui-nav-session-management', $mode === AuthorityMode::Standalone);
        $this->assertMarker($content, 'ui-nav-managed-transitions', $role === UserRole::Owner);
        $this->assertMarker($content, 'ui-nav-personal-credentials', true);
        $this->assertMarker($content, 'ui-nav-installation-credentials', true);
    }

    /** @return iterable<string, array{AuthorityMode}> */
    public static function authorityModeProvider(): iterable
    {
        foreach (AuthorityMode::cases() as $mode) {
            yield $mode->value => [$mode];
        }
    }

    #[DataProvider('authorityModeProvider')]
    public function test_default_null_manifest_renders_the_same_unbranded_shell_for_every_role(AuthorityMode $mode): void
    {
        $published = require __DIR__.'/../config/built-for-cloud.php';
        config([
            'built-for-cloud.manifest' => $published['manifest'],
            'built-for-cloud.ui' => $published['ui'],
        ]);
        $this->setAuthority($mode);
        $this->assertNull(app()->make(LandingManifest::class));
        $layoutRenders = 0;
        View::composer('bfc::layout', static function () use (&$layoutRenders): void {
            $layoutRenders++;
        });
        $shells = [];

        foreach (UserRole::cases() as $role) {
            $rendersBeforeRequest = $layoutRenders;
            $response = $this->actingAsVersioned($this->user(
                $role,
                managed: $mode === AuthorityMode::Managed,
            ))->get('/bfc/ui');
            $content = (string) $response->getContent();

            $response->assertOk()
                ->assertSeeHtml('data-testid="ui-shell"')
                ->assertSeeHtml('data-testid="ui-navigation"')
                ->assertSeeHtml('<title></title>');
            $this->assertSame($rendersBeforeRequest + 1, $layoutRenders);
            $this->assertSame(1, substr_count($content, '<main>'));
            $this->assertSame(1, substr_count($content, 'data-testid="ui-shell"'));
            $this->assertStringNotContainsString('data-testid="ui-manifest', $content);
            $this->assertStringNotContainsString('data-app-slug=', $content);
            $this->assertStringNotContainsString('data-testid="ui-nav-', $content);
            $this->assertStringNotContainsString('<header', $content);
            $this->assertStringNotContainsString('<img', $content);
            $this->assertStringNotContainsString('<a ', $content);
            $shells[] = $content;
        }

        $this->assertCount(1, array_unique($shells));
    }

    /** @return iterable<string, array{array<string, mixed>, string}> */
    public static function invalidShellManifestProvider(): iterable
    {
        yield 'partial declaration' => [[
            'name' => 'Test App',
            'slug' => null,
            'description' => null,
            'icon' => null,
            'product_url' => null,
        ], '[slug]'];

        yield 'malformed declaration' => [[
            'name' => 'Test App',
            'slug' => 'test-app',
            'description' => 'A test-created app.',
            'icon' => '/icon.svg',
            'product_url' => 'https://scalpels.app/products/test-app',
        ], '[icon]'];
    }

    /** @param array<string, mixed> $manifest */
    #[DataProvider('invalidShellManifestProvider')]
    public function test_partial_or_malformed_shell_manifest_refuses_instead_of_being_omitted(array $manifest, string $field): void
    {
        config([
            'built-for-cloud.manifest' => $manifest,
            'built-for-cloud.ui.landing_page' => false,
        ]);
        $pageRenders = 0;
        View::composer('bfc::home', static function () use (&$pageRenders): void {
            $pageRenders++;
        });

        try {
            $this->withoutExceptionHandling()
                ->actingAsVersioned($this->user(UserRole::Member))
                ->get('/bfc/ui');
            $this->fail('The invalid manifest was silently omitted.');
        } catch (RuntimeException $exception) {
            $this->assertStringContainsString($field, $exception->getMessage());
        }

        $this->assertSame(0, $pageRenders);
    }

    /** @return iterable<string, array{UserRole}> */
    public static function roleProvider(): iterable
    {
        foreach (UserRole::cases() as $role) {
            yield $role->value => [$role];
        }
    }

    #[DataProvider('roleProvider')]
    public function test_public_landing_enters_real_standalone_login_and_returns_each_role_to_the_ui(UserRole $role): void
    {
        $user = $this->user($role, password: 'test-created-password');

        $this->get('/')
            ->assertOk()
            ->assertSeeHtml('data-testid="landing-ui-entry"')
            ->assertSee(url('/bfc/ui'));

        $login = $this->get('/bfc/ui');
        $login->assertRedirect(route('bfc.login', ['intended' => '/bfc/ui']));
        $this->get((string) $login->headers->get('Location'))
            ->assertOk()
            ->assertSeeHtml('name="intended" value="/bfc/ui"');

        $this->post('/bfc/login', [
            'email' => $user->email,
            'password' => 'test-created-password',
            'intended' => '/bfc/ui',
        ])->assertRedirect(route('bfc.ui.home', absolute: false));

        $this->get('/bfc/ui')
            ->assertOk()
            ->assertSeeHtml('data-testid="ui-shell"')
            ->assertSee('Test <Shell> Application');
    }

    public function test_unauthenticated_ui_entry_uses_current_mode_and_preserves_the_relative_request(): void
    {
        $this->get('/bfc/ui?test-created-section=credentials')
            ->assertRedirect(route('bfc.login', [
                'intended' => '/bfc/ui?test-created-section=credentials',
            ]));

        $this->setAuthority(AuthorityMode::Managed);
        $this->get('/bfc/ui?test-created-section=credentials')
            ->assertRedirect(route('bfc.managed.login', [
                'intended' => '/bfc/ui?test-created-section=credentials',
            ]));
    }

    public function test_explicit_unsafe_standalone_destinations_fall_back_to_the_ui_home(): void
    {
        $user = $this->user(UserRole::Member, password: 'test-created-password');

        foreach ([
            'https://outside.example.test/bfc/ui',
            '//outside.example.test/bfc/ui',
            '/%5coutside.example.test/bfc/ui',
            '/bfc/ui/../outside',
        ] as $index => $intended) {
            $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.'.($index + 1)])
                ->post('/bfc/login', [
                    'email' => $user->email,
                    'password' => 'test-created-password',
                    'intended' => $intended,
                ])->assertRedirect(route('bfc.ui.home', absolute: false));
        }
    }

    public function test_route_is_mounted_with_flags_off_and_pins_its_stack_and_ownership(): void
    {
        config([
            'built-for-cloud.ui.member_management' => false,
            'built-for-cloud.ui.personal_credentials' => false,
            'built-for-cloud.ui.installation_credentials' => false,
            'built-for-cloud.ui.session_management' => false,
            'built-for-cloud.ui.managed_transitions' => false,
        ]);
        $route = Route::getRoutes()->getByName('bfc.ui.home');
        $this->assertNotNull($route);
        $this->assertSame('bfc/ui', $route->uri());
        $this->assertSame(['GET', 'HEAD'], $route->methods());

        /** @var Router $router */
        $router = app('router');
        $middleware = $router->gatherRouteMiddleware($route);
        $this->assertSame(1, count(array_keys($middleware, EnsureUiAuthority::class, true)));
        // AC7 counts this gate once; it already carries the UI-specific mode-aware intended-login branches.
        $this->assertContains(EnsureUserIsAuthenticated::class, $middleware);

        $content = (string) $this->actingAsVersioned($this->user(UserRole::Owner))
            ->get('/bfc/ui')
            ->assertOk()
            ->getContent();
        $this->assertStringContainsString('data-testid="ui-navigation"', $content);
        $this->assertStringNotContainsString('data-testid="ui-nav-', $content);

    }

    public function test_match_time_ownership_refuses_a_late_ui_takeover_before_the_host_handler(): void
    {
        $this->actingAsVersioned($this->user(UserRole::Owner));
        $hostRuns = 0;

        /** @var Router $router */
        $router = app('router');
        $router->get('/bfc/ui', static function () use (&$hostRuns): string {
            $hostRuns++;

            return 'host-ui';
        })->name('host.ui');

        try {
            $this->withoutExceptionHandling()->get('/bfc/ui');
            $this->fail('The late UI takeover was served.');
        } catch (RuntimeException $exception) {
            $this->assertStringContainsString('reserved by the built-for-cloud package user interface', $exception->getMessage());
        }

        $this->assertSame(0, $hostRuns);
    }

    /** @return iterable<string, array{AuthorityMode, string, string, int}> */
    public static function refusedIdentityProvider(): iterable
    {
        yield 'inactive standalone user' => [AuthorityMode::Standalone, UserRole::Member->value, 'inactive', 403];
        yield 'unknown standalone role' => [AuthorityMode::Standalone, 'unknown-role', 'active', 403];
        yield 'inactive managed user' => [AuthorityMode::Managed, UserRole::Member->value, 'inactive', 403];
        yield 'unknown managed role' => [AuthorityMode::Managed, 'unknown-role', 'active', 403];
        yield 'removed managed membership' => [AuthorityMode::Managed, UserRole::Member->value, 'removed', 302];
        yield 'disabled managed membership' => [AuthorityMode::Managed, UserRole::Member->value, 'disabled', 302];
        yield 'stale managed membership' => [AuthorityMode::Managed, UserRole::Member->value, 'stale', 302];
    }

    #[DataProvider('refusedIdentityProvider')]
    public function test_refused_local_identities_never_render_the_page_action(
        AuthorityMode $mode,
        string $role,
        string $state,
        int $status,
    ): void {
        $this->setAuthority($mode);
        $user = $this->user(
            $role,
            status: $state === 'inactive' ? 'inactive' : 'active',
            managed: $mode === AuthorityMode::Managed,
            managedStatus: in_array($state, ['removed', 'disabled'], true) ? $state : 'active',
            stale: $state === 'stale',
        );
        Http::fake(Http::response([], 503));
        $pageRenders = 0;
        View::composer('bfc::home', static function () use (&$pageRenders): void {
            $pageRenders++;
        });

        $response = $this->actingAsVersioned($user)->get('/bfc/ui');

        $response->assertStatus($status);
        if ($status === 302) {
            $response->assertRedirect(route('bfc.managed.login', ['intended' => '/bfc/ui']));
        }
        $this->assertSame(0, $pageRenders);
    }

    public function test_no_session_and_no_delegated_door_ever_render_the_page_action(): void
    {
        $pageRenders = 0;
        View::composer('bfc::home', static function () use (&$pageRenders): void {
            $pageRenders++;
        });

        $this->get('/bfc/ui')
            ->assertRedirect(route('bfc.login', ['intended' => '/bfc/ui']));
        $this->assertSame(0, $pageRenders);

        // The delegated-entry door is RETIRED: there is no package route
        // a delegated operator can authenticate through to reach this
        // browser surface at all, so the delegation vector is now held
        // by the route set itself rather than by a refusal at the gate.
        // What stays pinned here is that the route no longer exists and
        // nothing replaced it with a disabled stub.
        $this->assertSame(
            [],
            array_values(array_filter(
                Route::getRoutes()->getRoutes(),
                static fn (RoutingRoute $route): bool => in_array($route->uri(), ['bfc/console/enter', 'bfc/console/chrome.js'], true),
            )),
        );
    }

    public function test_invalid_authority_has_one_404_gate_and_never_invokes_the_page_action(): void
    {
        DB::unprepared('DROP TRIGGER bfc_authority_reject_delete');
        DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->delete();
        $pageRenders = 0;
        View::composer('bfc::home', static function () use (&$pageRenders): void {
            $pageRenders++;
        });

        $this->get('/bfc/ui')->assertNotFound();
        $this->assertSame(0, $pageRenders);

        $nextRuns = 0;
        try {
            app(EnsureUiAuthority::class)->handle(
                Request::create('/bfc/ui'),
                static function () use (&$nextRuns) {
                    $nextRuns++;

                    return response('page action ran');
                },
            );
            $this->fail('Invalid authority reached the downstream page action.');
        } catch (NotFoundHttpException $exception) {
            $this->assertSame(404, $exception->getStatusCode());
        }

        $this->assertSame(0, $nextRuns);
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
            'connection_id' => 'ui-connection',
            'organization_id' => 'ui-organization',
            'installation_id' => 'ui-installation',
            'authority_base_url' => 'https://authority.example.test',
            'managed_connection_status' => 'active',
            'managed_connection_generation' => 2,
            'managed_connection_roster_version' => 3,
            'managed_connection_response_sequence' => 4,
        ]);
    }

    private function user(
        UserRole|string $role,
        string $status = 'active',
        ?string $password = null,
        bool $managed = false,
        string $managedStatus = 'active',
        bool $stale = false,
    ): User {
        $roleValue = $role instanceof UserRole ? $role->value : $role;
        $email = 'ui-'.bin2hex(random_bytes(5)).'@example.test';
        $user = User::query()->create([
            'name' => 'Test-created '.$roleValue,
            'email' => $email,
            'password' => $password === null ? null : Hash::make($password),
        ]);
        $attributes = [
            'role' => $roleValue,
            'status' => $status,
            'email_verified_at' => now(),
            'original_contact_email' => $email,
        ];

        if ($managed) {
            $attributes += [
                'scalpels_issuer' => 'https://issuer.example.test',
                'scalpels_connection_id' => 'ui-connection',
                'scalpels_id' => 'subject-'.$user->getKey(),
                'managed_membership_status' => $managedStatus,
                'managed_membership_role' => $roleValue,
                'managed_membership_generation' => 2,
                'managed_membership_roster_version' => 3,
                'managed_membership_response_sequence' => 4,
                'managed_membership_responded_at' => now()->toAtomString(),
                'membership_confirmed_at' => $stale ? now()->subHour() : now(),
            ];
        }

        $user->forceFill($attributes)->save();

        return $user;
    }

    private function assertMarker(string $content, string $marker, bool $visible): void
    {
        $count = substr_count($content, 'data-testid="'.$marker.'"');
        $this->assertSame($visible ? 1 : 0, $count, $marker);
    }
}
