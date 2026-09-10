<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\Database\Factories\CredentialFactory;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureStandaloneAuthority;
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

$vector = $argv[1] ?? '';

if (! in_array($vector, ['control', 'fqcn-alias', 'fqcn-group', 'alias-exclusion', 'fqcn-exclusion', 'exclusion-alias'], true)) {
    fwrite(STDERR, "Unknown authority-resolution vector.\n");
    exit(2);
}

final class BfcAuthorityResolutionState
{
    public static int $markerRuns = 0;
}

final class BfcAuthorityResolutionMarker
{
    public function handle(Request $request, Closure $next): Response
    {
        BfcAuthorityResolutionState::$markerRuns++;

        return $next($request);
    }
}

final class BfcAuthorityResolutionProvider extends ServiceProvider
{
    public function boot(Router $router): void
    {
        $this->app->booted(static function () use ($router): void {
            $vector = $_SERVER['BFC_AUTHORITY_RESOLUTION'] ?? '';

            if ($vector === 'fqcn-alias') {
                $router->aliasMiddleware(EnsureStandaloneAuthority::class, BfcAuthorityResolutionMarker::class);
                $router->get('/_bfc-test/authority-resolution-control', static fn (): string => 'host-control')
                    ->middleware(EnsureStandaloneAuthority::class);
            } elseif ($vector === 'fqcn-group') {
                $router->middlewareGroup(EnsureStandaloneAuthority::class, [BfcAuthorityResolutionMarker::class]);
                $router->get('/_bfc-test/authority-resolution-control', static fn (): string => 'host-control')
                    ->middleware(EnsureStandaloneAuthority::class);
            } elseif ($vector === 'exclusion-alias') {
                $router->aliasMiddleware('host.expel', EnsureStandaloneAuthority::class);

                foreach ($router->getRoutes() as $route) {
                    if (is_string($route->getName()) && str_starts_with($route->getName(), 'bfc.')) {
                        $route->withoutMiddleware('host.expel');
                    }
                }
            } elseif (in_array($vector, ['alias-exclusion', 'fqcn-exclusion'], true)) {
                $exclusion = $vector === 'alias-exclusion' ? 'bfc.standalone' : EnsureStandaloneAuthority::class;

                foreach ($router->getRoutes() as $route) {
                    if (is_string($route->getName()) && str_starts_with($route->getName(), 'bfc.')) {
                        $route->withoutMiddleware($exclusion);
                    }
                }
            }
        });
    }
}

$_SERVER['BFC_AUTHORITY_RESOLUTION'] = $vector;

$case = new class('testProbe') extends TestCase
{
    /** @return list<class-string> */
    protected function getPackageProviders($app): array
    {
        return [BuiltForCloudServiceProvider::class, BfcAuthorityResolutionProvider::class];
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
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('a', 32)));
    }

    public function runProbe(): bool
    {
        parent::setUp();
        $this->artisan('migrate:fresh', ['--force' => true])->run();
        Notification::fake();

        $vector = $_SERVER['BFC_AUTHORITY_RESOLUTION'] ?? '';

        $owner = $this->user('resolution-owner@example.test', UserRole::Owner, 'original resolution password');
        $member = $this->user('resolution-member@example.test', UserRole::Member, 'original resolution password');
        $credential = CredentialFactory::new()->forUser((string) $owner->getKey())->create();

        $resetToken = 'resolution-reset-'.bin2hex(random_bytes(16));
        $resetHash = hash('sha256', $resetToken);
        DB::table('password_reset_tokens')->insert([
            'email' => $member->email,
            'token' => $resetHash,
            'created_at' => now(),
        ]);

        $invitationToken = 'resolution-invitation-'.bin2hex(random_bytes(16));
        $invitation = Invitation::query()->create([
            'id' => (string) Str::uuid(),
            'email' => 'resolution-invitee@example.test',
            'token' => Invitation::hashToken($invitationToken),
            'role' => UserRole::Member->value,
            'expires_at' => now()->addHour(),
        ]);

        InstallationAuthority::change(InstallationAuthority::current(), AuthorityMode::Managed);

        $tokenLookups = 0;
        $sessionQueries = 0;
        DB::listen(static function (QueryExecuted $query) use (&$sessionQueries, &$tokenLookups): void {
            $sql = strtolower(ltrim($query->sql));

            if (str_starts_with($sql, 'select')
                && (str_contains($sql, 'password_reset_tokens') || str_contains($sql, 'invitations'))) {
                $tokenLookups++;
            }

            if (str_contains($sql, 'sessions')) {
                $sessionQueries++;
            }
        });

        $control = in_array($vector, ['fqcn-alias', 'fqcn-group'], true)
            ? $this->get('/_bfc-test/authority-resolution-control')
            : null;

        $responses = [
            $this->get('/bfc/login'),
            $this->post('/bfc/login', ['email' => $owner->email, 'password' => 'original resolution password']),
            $this->get('/bfc/forgot-password'),
            $this->post('/bfc/forgot-password', ['email' => $member->email]),
            $this->get('/bfc/reset-password/'.$resetToken),
            $this->withCookie(StandaloneHandoff::COOKIE, 'stale-resolution-handoff')->get('/bfc/reset-password'),
            $this->withCookie(StandaloneHandoff::COOKIE, 'stale-resolution-handoff')->post('/bfc/reset-password', [
                'token' => $resetToken,
                'email' => $member->email,
                'password' => 'changed resolution password',
                'password_confirmation' => 'changed resolution password',
            ]),
            $this->get('/bfc/invitations/'.$invitationToken),
            $this->withCookie(StandaloneHandoff::COOKIE, 'stale-resolution-handoff')->get('/bfc/invitations/accept'),
            $this->withCookie(StandaloneHandoff::COOKIE, 'stale-resolution-handoff')->post('/bfc/invitations/accept', [
                'token' => $invitationToken,
                'name' => 'Resolution Invitee',
                'password' => 'resolution invitation password',
                'password_confirmation' => 'resolution invitation password',
            ]),
            $this->get('/bfc/members'),
            $this->get('/bfc/me/sessions'),
        ];

        $authenticated = $this->isAuthenticated();

        /** @var Router $router */
        $router = $this->app['router'];
        $resolved = [];

        foreach (self::standaloneRouteNames() as $name) {
            $route = $router->getRoutes()->getByName($name);

            if (! $route instanceof Route) {
                fwrite(STDERR, "route-missing:{$name}\n");

                return false;
            }

            $resolved[$name] = in_array(
                EnsureStandaloneAuthority::class,
                $router->resolveMiddleware($route->middleware(), $route->excludedMiddleware()),
                true,
            );
        }

        $tokenLookupsAtSweepEnd = $tokenLookups;
        $sessionQueriesAtSweepEnd = $sessionQueries;

        Notification::assertNothingSent();

        if ($vector === 'control') {
            foreach ($responses as $index => $response) {
                if ($response->getStatusCode() !== 404) {
                    fwrite(STDERR, "control-status-{$index}-{$response->getStatusCode()}\n");

                    return false;
                }
            }

            if (in_array(false, $resolved, true)) {
                fwrite(STDERR, 'control-authority-not-resolved:'.
                    implode(',', array_keys(array_filter($resolved, static fn (bool $holds): bool => ! $holds)))."\n");

                return false;
            }
        } else {
            foreach ($responses as $index => $response) {
                if ($response->getStatusCode() !== 500) {
                    fwrite(STDERR, "refusal-status-{$index}-{$response->getStatusCode()}\n");

                    return false;
                }
            }

            if (in_array(true, $resolved, true)) {
                fwrite(STDERR, 'attack-authority-still-resolved:'.
                    implode(',', array_keys(array_filter($resolved)))."\n");

                return false;
            }
        }

        foreach ($responses as $index => $response) {
            $handoffCookie = $response->getCookie(StandaloneHandoff::COOKIE, false);

            if ($handoffCookie !== null && $handoffCookie->getExpiresTime() >= now()->timestamp) {
                fwrite(STDERR, "handoff-issued-{$index}\n");

                return false;
            }
        }

        $checks = [
            'control-route' => $control === null || ($control->getStatusCode() === 200 && $control->getContent() === 'host-control'),
            'marker-runs' => $control === null ? BfcAuthorityResolutionState::$markerRuns === 0 : BfcAuthorityResolutionState::$markerRuns >= 1,
            'token-lookups' => $tokenLookupsAtSweepEnd === 0,
            'session-queries' => $sessionQueriesAtSweepEnd === 0,
            'authentication' => ! $authenticated,
            'password' => Hash::check('original resolution password', (string) $member->refresh()->password),
            'reset' => DB::table('password_reset_tokens')->where('email', $member->email)->value('token') === $resetHash,
            'invitation' => $invitation->refresh()->accepted_at === null,
            'invitee-count' => User::query()->where('email', 'resolution-invitee@example.test')->doesntExist(),
            'credential' => Credential::query()->whereKey($credential->getKey())->whereNull('revoked_at')->exists(),
        ];

        $failures = array_keys(array_filter($checks, static fn (bool $passed): bool => ! $passed));

        if ($failures !== []) {
            fwrite(STDERR, 'failed-checks:'.implode(',', $failures).PHP_EOL);

            return false;
        }

        return true;
    }

    /** @return list<string> */
    private static function standaloneRouteNames(): array
    {
        return [
            'bfc.login', 'bfc.login.store', 'bfc.logout',
            'bfc.password.request', 'bfc.password.email',
            'bfc.password.reset', 'bfc.password.reset.form', 'bfc.password.update',
            'bfc.invitations.accept', 'bfc.invitations.accept.form', 'bfc.invitations.accept.store',
            'bfc.members.index', 'bfc.members.invitations.store', 'bfc.members.role.update', 'bfc.members.destroy',
            'bfc.sessions.index', 'bfc.sessions.destroy-others', 'bfc.sessions.destroy',
        ];
    }

    private function user(string $email, UserRole $role, string $password): User
    {
        $user = User::query()->create([
            'name' => 'Authority Resolution User',
            'email' => $email,
            'password' => Hash::make($password),
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
    fwrite(STDERR, "The authority-resolution vector bypassed a package gate.\n");
    exit(1);
}

fwrite(STDOUT, 'standalone-authority-resolution-'.($_SERVER['BFC_AUTHORITY_RESOLUTION'] ?? $vector)."-refused\n");
