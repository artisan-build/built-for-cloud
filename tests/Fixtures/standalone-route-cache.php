<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\Database\Factories\CredentialFactory;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\Invitation;
use ArtisanBuild\BuiltForCloud\StandaloneHandoff;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Routing\CompiledRouteCollection;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Str;
use Orchestra\Testbench\TestCase;
use Symfony\Component\Process\Process;

require __DIR__.'/../../vendor/autoload.php';

$mode = $argv[1] ?? '';

final class BfcRouteCacheHostState
{
    public static int $hostRuns = 0;
}

if ($mode === 'generate') {
    $destination = $argv[2] ?? '';

    if ($destination === '') {
        fwrite(STDERR, "A destination path is required.\n");
        exit(2);
    }

    $case = new class('testProbe') extends TestCase
    {
        /** @return list<class-string> */
        protected function getPackageProviders($app): array
        {
            return [BuiltForCloudServiceProvider::class];
        }

        /** @param Application $app */
        protected function getEnvironmentSetUp($app): void
        {
            $app['config']->set('auth.guards', []);
            $app['config']->set('auth.providers', []);
            $app['config']->set('built-for-cloud.surfaces.data_migrations', false);
            $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('r', 32)));
        }

        public function generate(string $destination): array
        {
            parent::setUp();

            // Run the real artisan CLI as its own process: framework route
            // caching boots a second application from the Testbench
            // skeleton, and booting that second app inside this already-
            // booted TestCase process loses the skeleton's yaml providers
            // on newer framework static-state handling. One process, one
            // boot — exactly how a consuming app runs `php artisan
            // route:cache`.
            $cachePath = $this->app->getCachedRoutesPath();
            $cacheDir = dirname($cachePath);
            $before = is_dir($cacheDir) ? scandir($cacheDir) : [];

            try {
                @unlink($cachePath);

                $repoRoot = dirname(__DIR__, 2);
                $artisan = $repoRoot.'/vendor/orchestra/testbench-core/laravel/artisan';
                $process = new Process(
                    [PHP_BINARY, $artisan, 'route:cache'],
                    $repoRoot,
                    ['TESTBENCH_WORKING_PATH' => $repoRoot],
                );
                $exitCode = $process->run();

                if ($exitCode !== 0 || ! is_file($cachePath)) {
                    return ['exit' => $exitCode, 'cache' => false, 'copied' => false, 'size' => 0, 'contains' => false];
                }

                $contents = file_get_contents($cachePath);
                $copied = copy($cachePath, $destination);

                return [
                    'exit' => $exitCode,
                    'cache' => true,
                    'copied' => $copied,
                    'size' => is_string($contents) ? strlen($contents) : 0,
                    'contains' => is_string($contents) && str_contains($contents, 'bfc.password.reset.form'),
                ];
            } finally {
                @unlink($cachePath);

                $after = is_dir($cacheDir) ? scandir($cacheDir) : [];

                foreach (array_diff($after, $before) as $created) {
                    if (is_file($cacheDir.'/'.$created)) {
                        @unlink($cacheDir.'/'.$created);
                    }
                }
            }
        }

        public function test_probe(): void {}
    };

    try {
        $result = $case->generate($destination);
        fwrite(STDOUT, json_encode($result, JSON_THROW_ON_ERROR).PHP_EOL);
        exit($result['exit'] === 0 && $result['cache'] && $result['copied'] && $result['contains'] ? 0 : 1);
    } catch (Throwable $exception) {
        fwrite(STDERR, $exception::class.': '.$exception->getMessage().PHP_EOL);
        exit(1);
    }
}

if ($mode !== 'load') {
    fwrite(STDERR, "Unknown route-cache probe mode.\n");
    exit(2);
}

$payload = $argv[2] ?? '';

if (! is_file($payload)) {
    fwrite(STDERR, "The generated route cache is unavailable.\n");
    exit(2);
}

$case = new class('testProbe') extends TestCase
{
    /** @return list<class-string> */
    protected function getPackageProviders($app): array
    {
        return [BuiltForCloudServiceProvider::class];
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
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('k', 32)));
    }

    public function load(string $payload): bool
    {
        parent::setUp();
        $this->artisan('migrate:fresh', ['--force' => true])->run();
        Notification::fake();

        // Load the generated payload exactly the way the framework's cached
        // route stub does: the file itself calls setCompiledRoutes().
        require $payload;

        /** @var Router $router */
        $router = $this->app['router'];

        if ($router->getRoutes()::class !== CompiledRouteCollection::class) {
            fwrite(STDERR, 'collection:'.$router->getRoutes()::class.PHP_EOL);

            return false;
        }

        $owner = $this->user('cache-owner@example.test', UserRole::Owner, 'owner cache password');
        $member = $this->user('cache-member@example.test', UserRole::Member, 'member cache password');
        $credential = CredentialFactory::new()->forUser((string) $owner->getKey())->create();

        $resetToken = 'cache-reset-'.bin2hex(random_bytes(16));
        DB::table('password_reset_tokens')->insert([
            'email' => $member->email,
            'token' => hash('sha256', $resetToken),
            'created_at' => now(),
        ]);

        $invitationToken = 'cache-invitation-'.bin2hex(random_bytes(16));
        $invitation = Invitation::query()->create([
            'id' => (string) Str::uuid(),
            'email' => 'cache-invitee@example.test',
            'token' => Invitation::hashToken($invitationToken),
            'role' => UserRole::Member->value,
            'expires_at' => now()->addHour(),
        ]);

        // Phase A — the full standalone surface on the compiled table, in
        // Standalone mode. Nothing here may self-refuse.
        $steps = [];

        $steps['login-form'] = $this->get('/bfc/login')->getStatusCode();
        $steps['forgot-form'] = $this->get('/bfc/forgot-password')->getStatusCode();

        $bearer = $this->get('/bfc/reset-password/'.$resetToken);
        $steps['reset-bearer'] = $bearer->getStatusCode();
        $resetHandoff = $bearer->getCookie(StandaloneHandoff::COOKIE)?->getValue();

        if (! is_string($resetHandoff)) {
            fwrite(STDERR, 'reset-handoff-missing'.PHP_EOL);

            return false;
        }

        $steps['reset-form'] = $this->withCookie(StandaloneHandoff::COOKIE, $resetHandoff)
            ->get('/bfc/reset-password')->getStatusCode();
        $steps['reset-update'] = $this->withCookie(StandaloneHandoff::COOKIE, $resetHandoff)
            ->post('/bfc/reset-password', [
                'token' => $resetToken,
                'email' => $member->email,
                'password' => 'changed cache password',
                'password_confirmation' => 'changed cache password',
            ])->getStatusCode();

        $steps['forgot-store'] = $this->post('/bfc/forgot-password', ['email' => $member->email])->getStatusCode();

        $invitationBearer = $this->get('/bfc/invitations/'.$invitationToken);
        $steps['invitation-bearer'] = $invitationBearer->getStatusCode();
        $invitationHandoff = $invitationBearer->getCookie(StandaloneHandoff::COOKIE)?->getValue();

        if (! is_string($invitationHandoff)) {
            fwrite(STDERR, 'invitation-handoff-missing'.PHP_EOL);

            return false;
        }

        $steps['invitation-form'] = $this->withCookie(StandaloneHandoff::COOKIE, $invitationHandoff)
            ->get('/bfc/invitations/accept')->getStatusCode();
        $steps['invitation-store'] = $this->withCookie(StandaloneHandoff::COOKIE, $invitationHandoff)
            ->post('/bfc/invitations/accept', [
                'token' => $invitationToken,
                'name' => 'Cache Invitee',
                'password' => 'invitation cache password',
                'password_confirmation' => 'invitation cache password',
            ])->getStatusCode();

        $steps['login-error'] = $this->post('/bfc/login', [
            'email' => $owner->email,
            'password' => 'wrong cache password',
        ])->getStatusCode();

        $invitee = User::query()->where('email', 'cache-invitee@example.test')->first();

        if (! $invitee instanceof User) {
            fwrite(STDERR, 'invitee-missing'.PHP_EOL);

            return false;
        }

        // Authenticate through the real (compiled) login ceremony rather
        // than actingAs, so the authenticated surface proves itself.
        $steps['login-success'] = $this->post('/bfc/login', [
            'email' => $owner->email,
            'password' => 'owner cache password',
        ])->getStatusCode();

        $foreignSessionId = (string) Str::uuid();
        DB::table('sessions')->insert([
            'id' => $foreignSessionId,
            'user_id' => (string) $owner->getKey(),
            'ip_address' => '127.0.0.1',
            'user_agent' => 'route-cache-fixture',
            'payload' => base64_encode(serialize([])),
            'last_activity' => now()->timestamp,
        ]);

        $steps['members-index'] = $this->get('/bfc/members')->getStatusCode();
        $steps['members-invite'] = $this->post('/bfc/members/invitations', [
            'email' => 'cache-future@example.test',
            'role' => 'member',
        ])->getStatusCode();
        $steps['sessions-index'] = $this->get('/bfc/me/sessions')->getStatusCode();
        $steps['sessions-destroy'] = $this->delete('/bfc/me/sessions/'.$foreignSessionId, ['password' => 'owner cache password'])->getStatusCode();
        $steps['sessions-destroy-others'] = $this->delete('/bfc/me/sessions/others', ['password' => 'owner cache password'])->getStatusCode();
        $steps['members-role'] = $this->put('/bfc/members/'.$invitee->getKey().'/role', ['role' => 'admin'])->getStatusCode();
        $steps['members-destroy'] = $this->delete('/bfc/members/'.$member->getKey())->getStatusCode();
        $steps['logout'] = $this->post('/bfc/logout')->getStatusCode();

        foreach ($steps as $name => $status) {
            if (! in_array($status, [200, 302], true)) {
                fwrite(STDERR, "standalone-step-{$name}-status-{$status}".PHP_EOL);

                return false;
            }
        }

        if (! Hash::check('changed cache password', (string) $member->refresh()->password)
            || $invitee->refresh()->role !== UserRole::Admin->value
            || $member->refresh()->status === 'active'
            || ! Credential::query()->whereKey($credential->getKey())->whereNull('revoked_at')->exists()) {
            fwrite(STDERR, sprintf(
                'standalone-side-effects-wrong password=%d invitee-role=%s member-status=%s credential=%d'.PHP_EOL,
                (int) Hash::check('changed cache password', (string) $member->refresh()->password),
                (string) $invitee->refresh()->role,
                (string) $member->refresh()->status,
                (int) Credential::query()->whereKey($credential->getKey())->whereNull('revoked_at')->exists(),
            ));

            return false;
        }

        // Baseline for the takeover phase, captured after every intended
        // Standalone side effect has landed (member deactivation clears the
        // member's reset row by design, so the baseline must come after it).
        $resetBaseline = DB::table('password_reset_tokens')->where('email', $member->email)->first();
        $resetBaselineHash = is_object($resetBaseline) ? (string) $resetBaseline->token : '';
        $resetBaselineCount = DB::table('password_reset_tokens')->where('email', $member->email)->count();

        // Phase B — Managed mode: the same compiled surface refuses.
        InstallationAuthority::change(InstallationAuthority::current(), AuthorityMode::Managed);

        $managed = [
            $this->get('/bfc/login'),
            $this->post('/bfc/login', ['email' => $owner->email, 'password' => 'owner cache password']),
            $this->get('/bfc/forgot-password'),
            $this->post('/bfc/forgot-password', ['email' => $member->email]),
            $this->get('/bfc/reset-password/managed-bearer-probe'),
            $this->withCookie(StandaloneHandoff::COOKIE, 'expired-managed-handoff')->get('/bfc/reset-password'),
            $this->post('/bfc/reset-password', [
                'token' => 'managed-bearer-probe',
                'email' => $member->email,
                'password' => 'managed probe password',
                'password_confirmation' => 'managed probe password',
            ]),
            $this->get('/bfc/invitations/managed-bearer-probe'),
            $this->get('/bfc/invitations/accept'),
            $this->actingAs($owner)->get('/bfc/members'),
            $this->actingAs($owner)->get('/bfc/me/sessions'),
        ];

        foreach ($managed as $index => $response) {
            if ($response->getStatusCode() !== 404) {
                fwrite(STDERR, "managed-step-{$index}-status-{$response->getStatusCode()}".PHP_EOL);

                return false;
            }
        }

        if (! Hash::check('changed cache password', (string) $member->refresh()->password)) {
            fwrite(STDERR, 'managed-password-mutated'.PHP_EOL);

            return false;
        }

        // Phase C — takeovers registered after the cache is loaded still
        // refuse before the host handler and before any package side effect.
        InstallationAuthority::change(InstallationAuthority::current(), AuthorityMode::Standalone);

        $tokenLookups = 0;
        $sessionWrites = 0;
        DB::listen(static function (QueryExecuted $query) use (&$tokenLookups, &$sessionWrites): void {
            $sql = strtolower(ltrim($query->sql));

            if (str_starts_with($sql, 'select')
                && (str_contains($sql, 'password_reset_tokens') || str_contains($sql, 'invitations'))) {
                $tokenLookups++;
            }

            if ((str_starts_with($sql, 'insert') || str_starts_with($sql, 'update'))
                && str_contains($sql, 'sessions')) {
                $sessionWrites++;
            }
        });

        $router->get('/host-login', static function (): string {
            BfcRouteCacheHostState::$hostRuns++;

            return 'host-login';
        })->name('bfc.login');

        $router->get('/bfc/login', static function (): string {
            BfcRouteCacheHostState::$hostRuns++;

            return 'host-pair';
        })->name('host.login');

        $router->post('/bfc/login', static function (): string {
            BfcRouteCacheHostState::$hostRuns++;

            return 'host-post';
        })->name('host.login.post');

        $router->get('/bfc/reset-password/{token}', static function (string $token): string {
            BfcRouteCacheHostState::$hostRuns++;

            return 'host-bearer';
        })->name('host.reset');

        foreach ([
            ['/host-login', 'GET'],
            ['/bfc/login', 'GET'],
            ['/bfc/login', 'POST'],
            ['/bfc/reset-password/takeover-bearer-probe', 'GET'],
        ] as [$uri, $method]) {
            try {
                $this->withoutExceptionHandling();
                match ($method) {
                    'GET' => $this->get($uri),
                    'POST' => $this->post($uri, []),
                };
                fwrite(STDERR, "takeover-{$method}-{$uri}-served".PHP_EOL);

                return false;
            } catch (RuntimeException $exception) {
                if (! str_contains($exception->getMessage(), 'reserved by built-for-cloud standalone authentication')) {
                    fwrite(STDERR, 'takeover-unexpected:'.$exception->getMessage().PHP_EOL);

                    return false;
                }
            }
        }

        $hostRuns = BfcRouteCacheHostState::$hostRuns;
        $takeoverTokenLookups = $tokenLookups;
        $takeoverSessionWrites = $sessionWrites;
        $passwordHeld = Hash::check('changed cache password', (string) $member->refresh()->password);
        $resetHashHeld = (string) DB::table('password_reset_tokens')->where('email', $member->email)->value('token');
        $resetCountHeld = DB::table('password_reset_tokens')->where('email', $member->email)->count();
        $inviteeCount = User::query()->where('email', 'cache-invitee@example.test')->count();
        $credentialLive = Credential::query()->whereKey($credential->getKey())->whereNull('revoked_at')->exists();

        $checks = [
            'host_runs' => $hostRuns === 0,
            'token_lookups' => $takeoverTokenLookups === 0,
            'session_writes' => $takeoverSessionWrites === 0,
            'password' => $passwordHeld,
            'reset_hash' => $resetHashHeld === $resetBaselineHash && $resetCountHeld === $resetBaselineCount,
            'invitee_count' => $inviteeCount === 1,
            'credential_live' => $credentialLive,
        ];

        $failures = array_keys(array_filter($checks, static fn (bool $passed): bool => ! $passed));

        if ($failures !== []) {
            fwrite(STDERR, 'takeover-failed-checks:'.implode(',', $failures).PHP_EOL);

            return false;
        }

        return true;
    }

    private function user(string $email, UserRole $role, string $password): User
    {
        $user = User::query()->create([
            'name' => 'Route Cache User',
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
    $valid = $case->load($payload);
} catch (Throwable $exception) {
    fwrite(STDERR, $exception::class.': '.$exception->getMessage().PHP_EOL);
    exit(1);
}

if (! $valid) {
    fwrite(STDERR, "The compiled standalone route table failed its ownership contract.\n");
    exit(1);
}

fwrite(STDOUT, "standalone-route-cache-ok\n");
