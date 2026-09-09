<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\Database\Factories\CredentialFactory;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureStandaloneAuthority;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAuthenticated;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\Invitation;
use ArtisanBuild\BuiltForCloud\StandaloneHandoff;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Str;
use Orchestra\Testbench\TestCase;
use Symfony\Component\HttpFoundation\Response;

require __DIR__.'/../../vendor/autoload.php';

final class BfcMiddlewareCollisionState
{
    public static int $hostRuns = 0;
}

final class BfcMiddlewareCollisionMarker
{
    public function handle(Request $request, Closure $next): Response
    {
        BfcMiddlewareCollisionState::$hostRuns++;

        return $next($request);
    }
}

final class BfcMiddlewareCollisionProvider extends ServiceProvider
{
    public function boot(Router $router): void
    {
        $this->app->booted(static function () use ($router): void {
            foreach (['bfc.standalone', 'bfc.auth', 'bfc.admin'] as $name) {
                $router->aliasMiddleware($name, BfcMiddlewareCollisionMarker::class);
                $router->middlewareGroup($name, [BfcMiddlewareCollisionMarker::class]);
            }

            $router->get('/_bfc-test/middleware-collision-control', static fn (): string => 'host-control')
                ->middleware('bfc.standalone');
        });
    }
}

$case = new class('testProbe') extends TestCase
{
    /** @return list<class-string> */
    protected function getPackageProviders($app): array
    {
        return [BuiltForCloudServiceProvider::class, BfcMiddlewareCollisionProvider::class];
    }

    /** @param Application $app */
    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('auth.defaults.guard', 'web');
        $app['config']->set('auth.guards.web', ['driver' => 'session', 'provider' => 'users']);
        $app['config']->set('auth.providers.users', ['driver' => 'eloquent', 'model' => User::class]);
        $app['config']->set('cache.default', 'array');
        $app['config']->set('session.driver', 'database');
        $app['config']->set('built-for-cloud.surfaces.data_migrations', false);
        $app['config']->set('app.debug', false);
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('c', 32)));
    }

    public function runProbe(): bool
    {
        parent::setUp();
        $this->artisan('migrate:fresh', ['--force' => true])->run();
        Notification::fake();

        $owner = $this->user('collision-owner@example.test', UserRole::Owner);
        $member = $this->user('collision-member@example.test', UserRole::Member);
        $credential = CredentialFactory::new()->forUser((string) $member->getKey())->create();
        $resetToken = 'collision-reset-'.bin2hex(random_bytes(16));
        $resetHash = hash('sha256', $resetToken);
        DB::table('password_reset_tokens')->insert([
            'email' => $member->email,
            'token' => $resetHash,
            'created_at' => now(),
        ]);
        $invitationToken = 'collision-invitation-'.bin2hex(random_bytes(16));
        $invitation = Invitation::query()->create([
            'id' => (string) Str::uuid(),
            'email' => 'collision-invitee@example.test',
            'token' => Invitation::hashToken($invitationToken),
            'role' => UserRole::Member->value,
            'expires_at' => now()->addHour(),
        ]);

        $resetHandoff = $this->get('/bfc/reset-password/'.$resetToken)->getCookie(StandaloneHandoff::COOKIE)?->getValue();
        $invitationHandoff = $this->get('/bfc/invitations/'.$invitationToken)->getCookie(StandaloneHandoff::COOKIE)?->getValue();

        if (! is_string($resetHandoff) || ! is_string($invitationHandoff)) {
            return false;
        }

        InstallationAuthority::change(InstallationAuthority::current(), AuthorityMode::Managed);
        $tokenLookups = 0;
        $sessionQueries = 0;
        DB::listen(static function (QueryExecuted $query) use (&$sessionQueries, &$tokenLookups): void {
            $sql = strtolower($query->sql);

            if (str_starts_with(ltrim($sql), 'select')
                && (str_contains($sql, 'password_reset_tokens') || str_contains($sql, 'invitations'))) {
                $tokenLookups++;
            }

            if (str_contains($sql, '"sessions"') || str_contains($sql, '`sessions`')) {
                $sessionQueries++;
            }
        });

        $control = $this->get('/_bfc-test/middleware-collision-control');
        $publicResponses = [
            $this->get('/bfc/login'),
            $this->post('/bfc/login', ['email' => $owner->email, 'password' => 'original collision password']),
            $this->get('/bfc/forgot-password'),
            $this->post('/bfc/forgot-password', ['email' => $member->email]),
            $this->get('/bfc/reset-password/'.$resetToken),
            $this->withCookie(StandaloneHandoff::COOKIE, $resetHandoff)->get('/bfc/reset-password'),
            $this->withCookie(StandaloneHandoff::COOKIE, $resetHandoff)->post('/bfc/reset-password', [
                'token' => $resetToken,
                'email' => $member->email,
                'password' => 'changed collision password',
                'password_confirmation' => 'changed collision password',
            ]),
            $this->get('/bfc/invitations/'.$invitationToken),
            $this->withCookie(StandaloneHandoff::COOKIE, $invitationHandoff)->get('/bfc/invitations/accept'),
            $this->withCookie(StandaloneHandoff::COOKIE, $invitationHandoff)->post('/bfc/invitations/accept', [
                'token' => $invitationToken,
                'name' => 'Collision Invitee',
                'password' => 'collision invitation password',
                'password_confirmation' => 'collision invitation password',
            ]),
        ];
        $authenticatedAfterPublicRoutes = $this->isAuthenticated();
        $responses = [
            ...$publicResponses,
            $this->actingAs($owner)->post('/bfc/logout'),
            $this->actingAs($owner)->get('/bfc/members'),
            $this->actingAs($owner)->post('/bfc/members/invitations', ['email' => 'blocked@example.test', 'role' => 'member']),
            $this->actingAs($owner)->put('/bfc/members/'.$member->getKey().'/role', ['role' => 'admin']),
            $this->actingAs($owner)->delete('/bfc/members/'.$member->getKey()),
            $this->actingAs($owner)->get('/bfc/me/sessions'),
            $this->actingAs($owner)->delete('/bfc/me/sessions/others', ['password' => 'original collision password']),
            $this->actingAs($owner)->delete('/bfc/me/sessions/other', ['password' => 'original collision password']),
        ];

        /** @var Router $router */
        $router = $this->app['router'];
        $standaloneRouteNames = [
            'bfc.login',
            'bfc.login.store',
            'bfc.logout',
            'bfc.password.request',
            'bfc.password.email',
            'bfc.password.reset',
            'bfc.password.reset.form',
            'bfc.password.update',
            'bfc.invitations.accept',
            'bfc.invitations.accept.form',
            'bfc.invitations.accept.store',
            'bfc.members.index',
            'bfc.members.invitations.store',
            'bfc.members.role.update',
            'bfc.members.destroy',
            'bfc.sessions.index',
            'bfc.sessions.destroy-others',
            'bfc.sessions.destroy',
        ];

        foreach ($standaloneRouteNames as $name) {
            $route = $router->getRoutes()->getByName($name);

            if (! $route instanceof Route
                || ! in_array(EnsureStandaloneAuthority::class, $router->gatherRouteMiddleware($route), true)) {
                return false;
            }
        }

        foreach (['bfc.logout', 'bfc.members.index', 'bfc.sessions.index'] as $name) {
            $route = $router->getRoutes()->getByName($name);

            if (! $route instanceof Route
                || ! in_array(EnsureUserIsAuthenticated::class, $router->gatherRouteMiddleware($route), true)) {
                return false;
            }
        }

        Notification::assertNothingSent();

        foreach ($responses as $index => $response) {
            if ($response->getStatusCode() !== 404) {
                fwrite(STDERR, "response-{$index}-status-{$response->getStatusCode()}\n");

                return false;
            }
        }

        foreach ([$responses[4], $responses[7]] as $bearerResponse) {
            $handoffCookie = $bearerResponse->getCookie(StandaloneHandoff::COOKIE, false);

            if ($handoffCookie !== null && $handoffCookie->getExpiresTime() >= now()->timestamp) {
                fwrite(STDERR, "managed-bearer-issued-handoff\n");

                return false;
            }
        }

        $checks = [
            'control-status' => $control->getStatusCode() === 200,
            'control-body' => $control->getContent() === 'host-control',
            'host-runs' => BfcMiddlewareCollisionState::$hostRuns === 1,
            'token-lookups' => $tokenLookups === 0,
            'session-queries' => $sessionQueries === 0,
            'authentication' => ! $authenticatedAfterPublicRoutes,
            'password' => Hash::check('original collision password', (string) $member->refresh()->password),
            'reset' => DB::table('password_reset_tokens')->where('email', $member->email)->value('token') === $resetHash,
            'invitation' => $invitation->refresh()->accepted_at === null,
            'user-count' => User::query()->where('email', 'collision-invitee@example.test')->doesntExist(),
            'member-role' => $member->refresh()->role === UserRole::Member->value,
            'member-status' => $member->status === 'active',
            'credential' => Credential::query()->whereKey($credential->getKey())->whereNull('revoked_at')->exists(),
        ];
        $failures = array_keys(array_filter($checks, static fn (bool $passed): bool => ! $passed));

        if ($failures !== []) {
            fwrite(STDERR, 'failed-checks:'.implode(',', $failures).PHP_EOL);
        }

        return $failures === [];
    }

    private function user(string $email, UserRole $role): User
    {
        $user = User::query()->create([
            'name' => 'Collision User',
            'email' => $email,
            'password' => Hash::make('original collision password'),
        ]);
        $user->forceFill([
            'role' => $role->value,
            'status' => 'active',
            'email_verified_at' => now(),
            'original_contact_email' => $email,
        ])->save();

        return $user;
    }

    public function test_probe(): void {}
};

try {
    $valid = $case->runProbe();
} catch (Throwable $exception) {
    fwrite(STDERR, $exception::class.': '.$exception->getMessage().PHP_EOL);
    exit(1);
}

if (! $valid) {
    fwrite(STDERR, "The standalone middleware collision bypassed a package gate.\n");
    exit(1);
}

fwrite(STDOUT, "standalone-middleware-collision-refused\n");
