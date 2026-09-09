<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\Invitation;
use ArtisanBuild\BuiltForCloud\StandaloneHandoff;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Closure;
use Illuminate\Contracts\Http\Kernel as KernelContract;
use Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse;
use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Response;

final class StandaloneDatabaseSessionsTest extends TestCase
{
    /** @var list<array{binding_matches: int, encoded_matches: int, decoded_matches: int, decoded: bool, transaction_level: int}> */
    private array $observedSessionWrites = [];

    private bool $readingObservedSessionWrite = false;

    protected function setUp(): void
    {
        parent::setUp();

        $this->artisan('migrate:fresh', ['--force' => true])->run();
    }

    /** @param Application $app */
    protected function getEnvironmentSetUp($app): void
    {
        parent::getEnvironmentSetUp($app);
        $app['config']->set('session.driver', 'database');
    }

    public function test_a_user_lists_and_revokes_only_their_own_other_sessions(): void
    {
        $user = User::query()->create([
            'name' => 'Session Owner',
            'email' => 'session-owner@example.test',
            'password' => Hash::make('session owner password'),
        ]);
        $other = User::query()->create([
            'name' => 'Other Session Owner',
            'email' => 'other-session-owner@example.test',
            'password' => Hash::make('other session password'),
        ]);

        foreach ([
            ['owned-other', $user->getKey(), '198.51.100.10'],
            ['foreign-session', $other->getKey(), '198.51.100.20'],
        ] as [$id, $userId, $ip]) {
            DB::table('sessions')->insert([
                'id' => $id,
                'user_id' => $userId,
                'ip_address' => $ip,
                'user_agent' => 'Test-created browser '.$id,
                'payload' => 'test',
                'last_activity' => now()->timestamp,
            ]);
        }

        $this->login($user, 'session owner password');
        $this->get('/bfc/me/sessions')
            ->assertOk()
            ->assertSee('198.51.100.10')
            ->assertDontSee('198.51.100.20')
            ->assertSeeHtml('data-testid="sessions-list"');

        $this->delete('/bfc/me/sessions/foreign-session', [
            'password' => 'session owner password',
        ])->assertNotFound();
        $this->delete('/bfc/me/sessions/owned-other', [
            'password' => 'session owner password',
        ])->assertRedirect();

        expect(DB::table('sessions')->where('id', 'owned-other')->exists())->toBeFalse()
            ->and(DB::table('sessions')->where('id', 'foreign-session')->exists())->toBeTrue();
    }

    public function test_revoke_others_preserves_the_current_and_foreign_sessions(): void
    {
        $user = User::query()->create([
            'name' => 'All Others Owner',
            'email' => 'all-others@example.test',
            'password' => Hash::make('all others password'),
        ]);
        $other = User::query()->create([
            'name' => 'Foreign Owner',
            'email' => 'foreign-others@example.test',
            'password' => Hash::make('foreign password'),
        ]);

        $this->login($user, 'all others password');
        foreach ([['another-owned', $user->getKey()], ['another-foreign', $other->getKey()]] as [$id, $userId]) {
            DB::table('sessions')->insert([
                'id' => $id,
                'user_id' => $userId,
                'payload' => 'test',
                'last_activity' => now()->timestamp,
            ]);
        }

        $this->delete('/bfc/me/sessions/others', ['password' => 'all others password'])->assertRedirect();

        expect(DB::table('sessions')->where('id', 'another-owned')->exists())->toBeFalse()
            ->and(DB::table('sessions')->where('id', 'another-foreign')->exists())->toBeTrue()
            ->and($this->isAuthenticated())->toBeTrue();
    }

    #[DataProvider('bearerPlacements')]
    public function test_password_reset_never_persists_any_bearer_source_and_allows_a_safe_retry(string $placement): void
    {
        $user = $this->eligibleUser('session-reset-'.$placement.'@example.test');
        $token = 'reset-'.bin2hex(random_bytes(32));
        DB::table('password_reset_tokens')->insert([
            'email' => $user->email,
            'token' => hash('sha256', $token),
            'created_at' => now(),
        ]);
        $bearerUrl = route('bfc.password.reset', ['token' => $token], false);
        $retryUrl = route('bfc.password.reset.form', absolute: false);
        [$postUrl, $input, $bearers] = $this->bearerSubmission('/bfc/reset-password', $token, $placement, [
            'email' => $user->email,
            'password' => 'short',
            'password_confirmation' => 'mismatch',
        ]);
        $this->observeCompletedSessionWrites($bearers);

        $response = $this->get($bearerUrl);
        $response->assertRedirect($retryUrl);
        $this->assertNull($response->getCookie((string) config('session.cookie'), false));
        $this->carryHandoffCookie($response);
        $this->assertObservedSessionWritesAreClean(0);

        $response = $this->get($retryUrl);
        $response->assertOk()->assertSee($user->email);
        $this->assertBearersAbsentFromPersistedSessions($bearers, $this->carryCurrentDatabaseSession($response));
        $this->assertObservedSessionWritesAreClean(1);

        $response = $this->post($postUrl, $input);

        expect(DB::table('password_reset_tokens')->where('email', $user->email)->value('token'))
            ->toBe(hash('sha256', $token));
        $this->assertBearersAbsentFromPersistedSessions($bearers, $this->carryCurrentDatabaseSession($response));
        $this->assertObservedSessionWritesAreClean(2);
        $response->assertRedirect($retryUrl)->assertSessionHasErrors(['password']);
        $response = $this->get($retryUrl);
        $response->assertOk()->assertSeeHtml('data-testid="password-reset-errors"');
        $this->assertBearersAbsentFromPersistedSessions($bearers, $this->carryCurrentDatabaseSession($response));
        $this->assertObservedSessionWritesAreClean(3);

        $input['password'] = 'corrected reset password';
        $input['password_confirmation'] = 'corrected reset password';
        $response = $this->post($postUrl, $input);
        $response->assertRedirect(route('bfc.login'));
        $this->assertBearersAbsentFromPersistedSessions($bearers, $this->carryCurrentDatabaseSession($response));
        $this->assertObservedSessionWritesAreClean(4);

        expect(Hash::check('corrected reset password', (string) $user->refresh()->password))->toBeTrue()
            ->and(DB::table('password_reset_tokens')->where('email', $user->email)->exists())->toBeFalse();

        $input['password'] = 'another reset password';
        $input['password_confirmation'] = 'another reset password';
        $response = $this->post($postUrl, $input);
        $response->assertRedirect($retryUrl)->assertSessionHasErrors(['email']);
        $this->assertBearersAbsentFromPersistedSessions($bearers, $this->carryCurrentDatabaseSession($response));
        $this->assertObservedSessionWritesAreClean(5);

        $response = $this->get($retryUrl);
        $response->assertNotFound()->assertDontSee($token);
        $this->assertBearersAbsentFromPersistedSessions($bearers, $this->carryCurrentDatabaseSession($response));
        $this->assertObservedSessionWritesAreClean(6);
    }

    #[DataProvider('bearerPlacements')]
    public function test_invitation_never_persists_any_bearer_source_and_allows_a_safe_retry(string $placement): void
    {
        $token = 'invite-'.bin2hex(random_bytes(32));
        $invitation = Invitation::factory()->create([
            'email' => 'session-invitee-'.$placement.'@example.test',
            'token' => Invitation::hashToken($token),
            'role' => UserRole::Member->value,
            'expires_at' => now()->addHour(),
        ]);
        $bearerUrl = route('bfc.invitations.accept', [
            'token' => $token,
            'intended' => '/domain',
        ], false);
        $retryUrl = route('bfc.invitations.accept.form', absolute: false);
        [$postUrl, $input, $bearers] = $this->bearerSubmission('/bfc/invitations/accept', $token, $placement, [
            'name' => 'Session Invitee',
            'password' => 'short',
            'password_confirmation' => 'mismatch',
            'intended' => '/domain',
        ]);
        $this->observeCompletedSessionWrites($bearers);

        $response = $this->get($bearerUrl);
        $response->assertRedirect($retryUrl);
        $this->assertNull($response->getCookie((string) config('session.cookie'), false));
        $this->carryHandoffCookie($response);
        $this->assertObservedSessionWritesAreClean(0);

        $response = $this->get($retryUrl);
        $response->assertOk()->assertSee($invitation->email);
        $this->assertBearersAbsentFromPersistedSessions($bearers, $this->carryCurrentDatabaseSession($response));
        $this->assertObservedSessionWritesAreClean(1);

        $response = $this->post($postUrl, $input);

        expect($invitation->refresh()->accepted_at)->toBeNull();
        $this->assertBearersAbsentFromPersistedSessions($bearers, $this->carryCurrentDatabaseSession($response));
        $this->assertObservedSessionWritesAreClean(2);
        $response->assertRedirect($retryUrl)->assertSessionHasErrors(['password']);
        $response = $this->get($retryUrl);
        $response->assertOk()->assertSeeHtml('data-testid="invitation-accept-errors"');
        $this->assertBearersAbsentFromPersistedSessions($bearers, $this->carryCurrentDatabaseSession($response));
        $this->assertObservedSessionWritesAreClean(3);

        $input['password'] = 'corrected invite password';
        $input['password_confirmation'] = 'corrected invite password';
        $response = $this->post($postUrl, $input);
        $response->assertRedirect('/domain');
        $this->assertBearersAbsentFromPersistedSessions($bearers, $this->carryCurrentDatabaseSession($response));
        $this->assertObservedSessionWritesAreClean(4);

        expect($invitation->refresh()->accepted_at)->not->toBeNull()
            ->and(User::query()->where('email', $invitation->email)->count())->toBe(1);

        $input['name'] = 'Replay';
        $input['password'] = 'another invite password';
        $input['password_confirmation'] = 'another invite password';
        $response = $this->post($postUrl, $input);
        $response->assertRedirect($retryUrl)->assertSessionHasErrors(['token']);
        $this->assertBearersAbsentFromPersistedSessions($bearers, $this->carryCurrentDatabaseSession($response));
        $this->assertObservedSessionWritesAreClean(5);

        $response = $this->get($retryUrl);
        $response->assertNotFound()->assertDontSee($token);
        $this->assertBearersAbsentFromPersistedSessions($bearers, $this->carryCurrentDatabaseSession($response));
        $this->assertObservedSessionWritesAreClean(6);
    }

    public function test_malformed_bearers_use_safe_local_fallbacks_without_persistence(): void
    {
        $malformedReset = str_repeat('r', 256);
        $response = $this->post('/bfc/reset-password?token='.$malformedReset, [
            'email' => 'malformed-reset@example.test',
            'password' => 'short',
            'password_confirmation' => 'mismatch',
        ]);
        $response->assertRedirect(route('bfc.password.reset.form', absolute: false))->assertSessionHasErrors(['email']);
        $this->assertBearersAbsentFromPersistedSessions([$malformedReset], $this->carryCurrentDatabaseSession($response));

        $malformedInvitation = str_repeat('i', 256);
        $response = $this->post('/bfc/invitations/accept?token='.$malformedInvitation, [
            'name' => 'Malformed Invitee',
            'password' => 'short',
            'password_confirmation' => 'mismatch',
        ]);
        $response->assertRedirect(route('bfc.invitations.accept.form', absolute: false))->assertSessionHasErrors(['token']);
        $this->assertBearersAbsentFromPersistedSessions([$malformedInvitation], $this->carryCurrentDatabaseSession($response));
    }

    public function test_managed_bearer_route_refusals_never_persist_urls_or_change_auth_state(): void
    {
        Notification::fake();
        $user = $this->eligibleUser('managed-session-reset@example.test');
        $password = (string) $user->password;
        $resetToken = 'managed-reset-'.bin2hex(random_bytes(32));
        $resetHash = hash('sha256', $resetToken);
        DB::table('password_reset_tokens')->insert([
            'email' => $user->email,
            'token' => $resetHash,
            'created_at' => now(),
        ]);
        $invitationToken = 'managed-invite-'.bin2hex(random_bytes(32));
        $invitation = Invitation::factory()->create([
            'email' => 'managed-session-invitee@example.test',
            'token' => Invitation::hashToken($invitationToken),
            'role' => UserRole::Member->value,
            'expires_at' => now()->addHour(),
        ]);
        InstallationAuthority::change(InstallationAuthority::current(), AuthorityMode::Managed);
        $this->observeCompletedSessionWrites([$resetToken, $invitationToken]);

        $response = $this->get(route('bfc.password.reset', [
            'token' => $resetToken,
            'email' => $user->email,
        ], false));
        $response->assertNotFound();
        $this->assertNull($response->getCookie((string) config('session.cookie'), false));
        $this->assertObservedSessionWritesAreClean(0);

        $response = $this->get(route('bfc.invitations.accept', [
            'token' => $invitationToken,
            'email' => $invitation->email,
        ], false));
        $response->assertNotFound();
        $this->assertNull($response->getCookie((string) config('session.cookie'), false));
        $this->assertObservedSessionWritesAreClean(0);
        expect(DB::table('sessions')->count())->toBe(0);

        expect((string) $user->refresh()->password)->toBe($password)
            ->and(DB::table('password_reset_tokens')->where('email', $user->email)->value('token'))->toBe($resetHash)
            ->and($invitation->refresh()->accepted_at)->toBeNull()
            ->and($this->isAuthenticated())->toBeFalse();
        Notification::assertNothingSent();
    }

    public function test_write_observer_detects_the_rejected_compensating_save_order(): void
    {
        $token = 'unsafe-order-'.bin2hex(random_bytes(32));
        $this->observeCompletedSessionWrites([$token]);

        /** @var Router $router */
        $router = app('router');
        $router->aliasMiddleware('bfc.test.unsafe-session-order', static function (Request $request, Closure $next): Response {
            try {
                return $next($request);
            } finally {
                $request->session()->forget(['_previous.url', '_previous.route']);
                $request->session()->save();
            }
        });
        $router->get('/_bfc-test/unsafe-session-order/{token}', static fn (): Response => response('unsafe-order-control'))
            ->middleware([
                EncryptCookies::class,
                AddQueuedCookiesToResponse::class,
                'bfc.test.unsafe-session-order',
                StartSession::class,
            ]);

        $response = $this->get('/_bfc-test/unsafe-session-order/'.$token);
        $response->assertOk()->assertSee('unsafe-order-control');

        expect(array_column($this->observedSessionWrites, 'decoded'))->toBe([true, true])
            ->and(array_column($this->observedSessionWrites, 'binding_matches'))->toBe([1, 0])
            ->and(array_column($this->observedSessionWrites, 'encoded_matches'))->toBe([0, 0])
            ->and(array_column($this->observedSessionWrites, 'decoded_matches'))->toBe([1, 0])
            ->and(array_column($this->observedSessionWrites, 'transaction_level'))->toBe([0, 0]);
        $this->assertBearersAbsentFromPersistedSessions([$token], $this->carryCurrentDatabaseSession($response));
    }

    #[DataProvider('globalBearerRoutes')]
    public function test_global_session_middleware_is_unsupported_and_the_tripwire_prevents_package_work(string $purpose): void
    {
        Notification::fake();
        $token = 'global-session-'.bin2hex(random_bytes(32));

        if ($purpose === StandaloneHandoff::PASSWORD_RESET) {
            $user = $this->eligibleUser('global-session-reset@example.test');
            DB::table('password_reset_tokens')->insert([
                'email' => $user->email,
                'token' => hash('sha256', $token),
                'created_at' => now(),
            ]);
            $path = route('bfc.password.reset', ['token' => $token], false);
        } else {
            $invitation = Invitation::factory()->create([
                'email' => 'global-session-invitee@example.test',
                'token' => Invitation::hashToken($token),
                'role' => UserRole::Member->value,
                'expires_at' => now()->addHour(),
            ]);
            $path = route('bfc.invitations.accept', ['token' => $token], false);
        }
        $userCount = User::query()->count();
        $credentialCount = Credential::query()->count();
        $tokenLookups = 0;

        DB::listen(static function (QueryExecuted $query) use (&$tokenLookups): void {
            $sql = strtolower($query->sql);

            if (str_starts_with(ltrim($sql), 'select')
                && (str_contains($sql, 'password_reset_tokens') || str_contains($sql, 'invitations'))) {
                $tokenLookups++;
            }
        });
        $this->observeCompletedSessionWrites([$token]);
        app(KernelContract::class)->pushMiddleware(StartSession::class);

        $response = $this->get($path);

        $response->assertInternalServerError()
            ->assertCookieMissing(StandaloneHandoff::COOKIE);
        expect($tokenLookups)->toBe(0)
            ->and(array_column($this->observedSessionWrites, 'binding_matches'))->toBe([1])
            ->and(array_column($this->observedSessionWrites, 'decoded_matches'))->toBe([1])
            ->and(User::query()->count())->toBe($userCount)
            ->and(Credential::query()->count())->toBe($credentialCount)
            ->and($this->isAuthenticated())->toBeFalse();

        if ($purpose === StandaloneHandoff::PASSWORD_RESET) {
            expect(DB::table('password_reset_tokens')->where('email', $user->email)->value('token'))
                ->toBe(hash('sha256', $token));
        } else {
            expect($invitation->refresh()->accepted_at)->toBeNull();
        }

        Notification::assertNothingSent();
    }

    #[DataProvider('cleanHandoffRoutes')]
    public function test_clean_handoff_pages_preserve_the_host_flash_lifecycle(string $routeName): void
    {
        $token = 'flash-lifecycle-'.bin2hex(random_bytes(32));
        if ($routeName === 'bfc.password.reset.form') {
            $user = $this->eligibleUser('flash-reset@example.test');
            DB::table('password_reset_tokens')->insert([
                'email' => $user->email,
                'token' => hash('sha256', $token),
                'created_at' => now(),
            ]);
            $bearerRoute = 'bfc.password.reset';
        } else {
            Invitation::factory()->create([
                'email' => 'flash-invitation@example.test',
                'token' => Invitation::hashToken($token),
                'role' => UserRole::Member->value,
                'expires_at' => now()->addHour(),
            ]);
            $bearerRoute = 'bfc.invitations.accept';
        }
        $handoffResponse = $this->get(route($bearerRoute, ['token' => $token], false));
        $this->carryHandoffCookie($handoffResponse);
        config()->set('session.block', true);
        config()->set('session.block_store', 'array');
        $this->observeCompletedSessionWrites([$token]);

        $route = Route::getRoutes()->getByName($routeName);
        $this->assertNotNull($route);
        /** @var Router $router */
        $router = app('router');
        $router->aliasMiddleware('bfc.test.host-flash', static function (Request $request, Closure $next): Response {
            $request->session()->flash('bfc_test_host_flash', 'next-request-only');
            $request->session()->put('bfc_test_host_persistent', 'persistent-value');

            return $next($request);
        });
        $route->middleware('bfc.test.host-flash');
        $route->flushController();

        $router->get('/_bfc-test/session-lifetime', static fn (Request $request) => response()->json([
            'flash' => $request->session()->get('bfc_test_host_flash'),
            'persistent' => $request->session()->get('bfc_test_host_persistent'),
        ]))->middleware([
            EncryptCookies::class,
            AddQueuedCookiesToResponse::class,
            StartSession::class,
        ]);

        $response = $this->get(route($routeName, absolute: false));
        $response->assertOk();
        $this->assertBearersAbsentFromPersistedSessions([$token], $this->carryCurrentDatabaseSession($response));
        $this->assertObservedSessionWritesAreClean(1);

        $response = $this->get('/_bfc-test/session-lifetime');
        $response->assertOk()
            ->assertJsonPath('flash', 'next-request-only')
            ->assertJsonPath('persistent', 'persistent-value');
        $this->carryCurrentDatabaseSession($response);
        $this->assertObservedSessionWritesAreClean(2);

        $response = $this->get('/_bfc-test/session-lifetime');
        $response->assertOk()
            ->assertJsonPath('flash', null)
            ->assertJsonPath('persistent', 'persistent-value');
        $this->carryCurrentDatabaseSession($response);
        $this->assertObservedSessionWritesAreClean(3);
    }

    private function login(User $user, string $password): void
    {
        $this->post('/bfc/login', [
            'email' => $user->email,
            'password' => $password,
        ])->assertRedirect('/');
    }

    private function eligibleUser(string $email): User
    {
        $user = User::query()->create([
            'name' => 'Session Recovery User',
            'email' => $email,
            'password' => Hash::make('original reset password'),
        ]);
        $user->forceFill([
            'role' => UserRole::Member->value,
            'status' => 'active',
            'email_verified_at' => now(),
            'original_contact_email' => $email,
        ])->save();

        return $user;
    }

    /**
     * @return array<string, array{string}>
     */
    public static function bearerPlacements(): array
    {
        return [
            'body only' => ['body'],
            'query only' => ['query'],
            'conflicting body and query' => ['conflicting'],
        ];
    }

    /**
     * @return array<string, array{string}>
     */
    public static function cleanHandoffRoutes(): array
    {
        return [
            'password reset' => ['bfc.password.reset.form'],
            'invitation acceptance' => ['bfc.invitations.accept.form'],
        ];
    }

    /** @return array<string, array{string}> */
    public static function globalBearerRoutes(): array
    {
        return [
            'password reset' => [StandaloneHandoff::PASSWORD_RESET],
            'invitation' => [StandaloneHandoff::INVITATION],
        ];
    }

    /**
     * @param  array<string, mixed>  $input
     * @return array{string, array<string, mixed>, list<string>}
     */
    private function bearerSubmission(string $url, string $token, string $placement, array $input): array
    {
        if ($placement === 'query') {
            return [$url.'?'.http_build_query(['token' => $token]), $input, [$token]];
        }

        $input['token'] = $token;

        if ($placement === 'conflicting') {
            $queryToken = 'query-'.bin2hex(random_bytes(32));

            return [$url.'?'.http_build_query(['token' => $queryToken]), $input, [$token, $queryToken]];
        }

        return [$url, $input, [$token]];
    }

    private function carryCurrentDatabaseSession(TestResponse $response): string
    {
        $cookieName = (string) config('session.cookie');
        $cookie = $response->getCookie($cookieName);

        $this->assertNotNull($cookie, 'The response did not carry its database-session cookie.');
        $sessionId = (string) $cookie->getValue();

        $this->assertNotSame('', $sessionId, 'The response cookie did not identify a valid database session.');
        $this->assertTrue(
            DB::table('sessions')->where('id', $sessionId)->exists(),
            'The request did not write the session row selected by its response cookie.',
        );
        $this->withCookie($cookieName, $sessionId);

        return $sessionId;
    }

    private function carryHandoffCookie(TestResponse $response): void
    {
        $cookie = $response->getCookie(StandaloneHandoff::COOKIE);
        $this->assertNotNull($cookie, 'The bearer route did not return a handoff cookie.');
        $this->withCookie(StandaloneHandoff::COOKIE, $cookie->getValue());
    }

    /** @param list<string> $bearers */
    private function assertBearersAbsentFromPersistedSessions(array $bearers, string $currentSessionId): void
    {
        $sessions = DB::table('sessions')->get(['id', 'payload']);

        $this->assertNotEmpty($sessions);
        $this->assertTrue(
            $sessions->contains(static fn (object $session): bool => $session->id === $currentSessionId),
            'The current request session row was absent from the complete payload scan.',
        );

        foreach ($sessions as $session) {
            $encoded = (string) $session->payload;
            $decoded = base64_decode($encoded, true);

            $this->assertIsString($decoded);

            foreach ($bearers as $bearer) {
                $this->assertFalse(str_contains($encoded, $bearer), 'Bearer found in an encoded session payload.');
                $this->assertFalse(str_contains($decoded, $bearer), 'Bearer found in a decoded session payload.');
            }
        }
    }

    /** @param list<string> $bearers */
    private function observeCompletedSessionWrites(array $bearers): void
    {
        $this->observedSessionWrites = [];

        DB::listen(function (QueryExecuted $query) use ($bearers): void {
            if ($this->readingObservedSessionWrite
                || preg_match('/^(insert into|update) ["`]?sessions["`]?/i', ltrim($query->sql)) !== 1) {
                return;
            }

            $this->readingObservedSessionWrite = true;

            try {
                $encodedMatches = 0;
                $decodedMatches = 0;
                $bindingMatches = 0;
                $decodedAll = true;

                foreach ($query->bindings as $binding) {
                    if (! is_string($binding)) {
                        continue;
                    }

                    $decodedBinding = base64_decode($binding, true);

                    foreach ($bearers as $bearer) {
                        $bindingMatches += (int) str_contains($binding, $bearer);
                        $bindingMatches += (int) (is_string($decodedBinding) && str_contains($decodedBinding, $bearer));
                    }
                }

                foreach ($query->connection->table('sessions')->pluck('payload') as $payload) {
                    $encoded = (string) $payload;
                    $decoded = base64_decode($encoded, true);
                    $decodedAll = $decodedAll && is_string($decoded);

                    foreach ($bearers as $bearer) {
                        $encodedMatches += (int) str_contains($encoded, $bearer);
                        $decodedMatches += (int) (is_string($decoded) && str_contains($decoded, $bearer));
                    }
                }

                $this->observedSessionWrites[] = [
                    'binding_matches' => $bindingMatches,
                    'encoded_matches' => $encodedMatches,
                    'decoded_matches' => $decodedMatches,
                    'decoded' => $decodedAll,
                    'transaction_level' => $query->connection->transactionLevel(),
                ];
            } finally {
                $this->readingObservedSessionWrite = false;
            }
        });
    }

    private function assertObservedSessionWritesAreClean(int $expectedWrites): void
    {
        $this->assertCount($expectedWrites, $this->observedSessionWrites, 'Unexpected database-session write count.');

        foreach ($this->observedSessionWrites as $write) {
            $this->assertTrue($write['decoded'], 'A completed session write did not contain a decodable payload.');
            $this->assertSame(0, $write['binding_matches'], 'Bearer found in completed session write bindings.');
            $this->assertSame(0, $write['encoded_matches'], 'Bearer found in an encoded completed session write.');
            $this->assertSame(0, $write['decoded_matches'], 'Bearer found in a decoded completed session write.');
            $this->assertSame(0, $write['transaction_level'], 'A session write had not completed outside a transaction.');
        }
    }
}
