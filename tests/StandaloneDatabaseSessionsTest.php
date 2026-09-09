<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\Invitation;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\DataProvider;

final class StandaloneDatabaseSessionsTest extends TestCase
{
    use RefreshDatabase;

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
        $retryUrl = route('bfc.password.reset', ['token' => $token, 'email' => $user->email], false);
        [$postUrl, $input, $bearers] = $this->bearerSubmission('/bfc/reset-password', $token, $placement, [
            'email' => $user->email,
            'password' => 'short',
            'password_confirmation' => 'mismatch',
        ]);

        $response = $this->post($postUrl, $input);

        expect(DB::table('password_reset_tokens')->where('email', $user->email)->value('token'))
            ->toBe(hash('sha256', $token));
        $this->assertBearersAbsentFromPersistedSessions($bearers, $this->carryCurrentDatabaseSession($response));
        $response->assertRedirect($retryUrl)->assertSessionHasErrors(['password']);
        $response = $this->get($retryUrl);
        $response->assertOk()->assertSeeHtml('data-testid="password-reset-errors"');
        $this->assertBearersAbsentFromPersistedSessions($bearers, $this->carryCurrentDatabaseSession($response));

        $input['password'] = 'corrected reset password';
        $input['password_confirmation'] = 'corrected reset password';
        $response = $this->post($postUrl, $input);
        $response->assertRedirect(route('bfc.login'));
        $this->assertBearersAbsentFromPersistedSessions($bearers, $this->carryCurrentDatabaseSession($response));

        expect(Hash::check('corrected reset password', (string) $user->refresh()->password))->toBeTrue()
            ->and(DB::table('password_reset_tokens')->where('email', $user->email)->exists())->toBeFalse();

        $input['password'] = 'another reset password';
        $input['password_confirmation'] = 'another reset password';
        $response = $this->post($postUrl, $input);
        $response->assertRedirect($retryUrl)->assertSessionHasErrors(['email']);
        $this->assertBearersAbsentFromPersistedSessions($bearers, $this->carryCurrentDatabaseSession($response));
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
        $retryUrl = route('bfc.invitations.accept', [
            'token' => $token,
            'email' => $invitation->email,
            'intended' => '/domain',
        ], false);
        [$postUrl, $input, $bearers] = $this->bearerSubmission('/bfc/invitations/accept', $token, $placement, [
            'name' => 'Session Invitee',
            'password' => 'short',
            'password_confirmation' => 'mismatch',
            'intended' => '/domain',
        ]);

        $response = $this->post($postUrl, $input);

        expect($invitation->refresh()->accepted_at)->toBeNull();
        $this->assertBearersAbsentFromPersistedSessions($bearers, $this->carryCurrentDatabaseSession($response));
        $response->assertRedirect($retryUrl)->assertSessionHasErrors(['password']);
        $response = $this->get($retryUrl);
        $response->assertOk()->assertSeeHtml('data-testid="invitation-accept-errors"');
        $this->assertBearersAbsentFromPersistedSessions($bearers, $this->carryCurrentDatabaseSession($response));

        $input['password'] = 'corrected invite password';
        $input['password_confirmation'] = 'corrected invite password';
        $response = $this->post($postUrl, $input);
        $response->assertRedirect('/domain');
        $this->assertBearersAbsentFromPersistedSessions($bearers, $this->carryCurrentDatabaseSession($response));

        expect($invitation->refresh()->accepted_at)->not->toBeNull()
            ->and(User::query()->where('email', $invitation->email)->count())->toBe(1);

        $input['name'] = 'Replay';
        $input['password'] = 'another invite password';
        $input['password_confirmation'] = 'another invite password';
        $response = $this->post($postUrl, $input);
        $response->assertRedirect($retryUrl)->assertSessionHasErrors(['token']);
        $this->assertBearersAbsentFromPersistedSessions($bearers, $this->carryCurrentDatabaseSession($response));
    }

    public function test_malformed_bearers_use_safe_local_fallbacks_without_persistence(): void
    {
        $malformedReset = str_repeat('r', 256);
        $response = $this->post('/bfc/reset-password?token='.$malformedReset, [
            'email' => 'malformed-reset@example.test',
            'password' => 'short',
            'password_confirmation' => 'mismatch',
        ]);
        $response->assertRedirect(route('bfc.password.request', absolute: false))->assertSessionHasErrors(['token']);
        $this->assertBearersAbsentFromPersistedSessions([$malformedReset], $this->carryCurrentDatabaseSession($response));

        $malformedInvitation = str_repeat('i', 256);
        $response = $this->post('/bfc/invitations/accept?token='.$malformedInvitation, [
            'name' => 'Malformed Invitee',
            'password' => 'short',
            'password_confirmation' => 'mismatch',
        ]);
        $response->assertRedirect(route('bfc.login', absolute: false))->assertSessionHasErrors(['token']);
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

        $response = $this->get(route('bfc.password.reset', [
            'token' => $resetToken,
            'email' => $user->email,
        ], false));
        $response->assertNotFound();
        $this->assertBearersAbsentFromPersistedSessions([$resetToken], $this->carryCurrentDatabaseSession($response));

        $response = $this->get(route('bfc.invitations.accept', [
            'token' => $invitationToken,
            'email' => $invitation->email,
        ], false));
        $response->assertNotFound();
        $this->assertBearersAbsentFromPersistedSessions(
            [$resetToken, $invitationToken],
            $this->carryCurrentDatabaseSession($response),
        );

        expect((string) $user->refresh()->password)->toBe($password)
            ->and(DB::table('password_reset_tokens')->where('email', $user->email)->value('token'))->toBe($resetHash)
            ->and($invitation->refresh()->accepted_at)->toBeNull()
            ->and($this->isAuthenticated())->toBeFalse();
        Notification::assertNothingSent();
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
}
