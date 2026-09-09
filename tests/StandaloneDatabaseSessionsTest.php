<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\Invitation;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;

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

    public function test_password_reset_validation_never_persists_its_bearer_and_allows_a_safe_retry(): void
    {
        $user = $this->eligibleUser('session-reset@example.test');
        $token = 'reset-'.bin2hex(random_bytes(32));
        DB::table('password_reset_tokens')->insert([
            'email' => $user->email,
            'token' => hash('sha256', $token),
            'created_at' => now(),
        ]);
        $retryUrl = '/bfc/reset-password/'.$token.'?email='.rawurlencode($user->email);

        $this->from($retryUrl)->post('/bfc/reset-password', [
            'token' => $token,
            'email' => $user->email,
            'password' => 'short',
            'password_confirmation' => 'mismatch',
        ])->assertRedirect($retryUrl)->assertSessionHasErrors(['password']);

        expect(DB::table('password_reset_tokens')->where('email', $user->email)->value('token'))
            ->toBe(hash('sha256', $token));
        $this->assertBearerAbsentFromPersistedSessions($token);
        $this->get($retryUrl)->assertOk()->assertSeeHtml('data-testid="password-reset-errors"');
        $this->assertBearerAbsentFromPersistedSessions($token);

        $this->post('/bfc/reset-password', [
            'token' => $token,
            'email' => $user->email,
            'password' => 'corrected reset password',
            'password_confirmation' => 'corrected reset password',
        ])->assertRedirect(route('bfc.login'));

        expect(Hash::check('corrected reset password', (string) $user->refresh()->password))->toBeTrue()
            ->and(DB::table('password_reset_tokens')->where('email', $user->email)->exists())->toBeFalse();

        $this->from($retryUrl)->post('/bfc/reset-password', [
            'token' => $token,
            'email' => $user->email,
            'password' => 'another reset password',
            'password_confirmation' => 'another reset password',
        ])->assertRedirect($retryUrl)->assertSessionHasErrors(['email']);
        $this->assertBearerAbsentFromPersistedSessions($token);
    }

    public function test_invitation_validation_never_persists_its_bearer_and_allows_a_safe_retry(): void
    {
        $token = 'invite-'.bin2hex(random_bytes(32));
        $invitation = Invitation::factory()->create([
            'email' => 'session-invitee@example.test',
            'token' => Invitation::hashToken($token),
            'role' => UserRole::Member->value,
            'expires_at' => now()->addHour(),
        ]);
        $retryUrl = '/bfc/invitations/'.$token.'?email=session-invitee%40example.test&intended=%2Fdomain';

        $this->from($retryUrl)->post('/bfc/invitations/accept', [
            'token' => $token,
            'name' => 'Session Invitee',
            'password' => 'short',
            'password_confirmation' => 'mismatch',
            'intended' => '/domain',
        ])->assertRedirect($retryUrl)->assertSessionHasErrors(['password']);

        expect($invitation->refresh()->accepted_at)->toBeNull();
        $this->assertBearerAbsentFromPersistedSessions($token);
        $this->get($retryUrl)->assertOk()->assertSeeHtml('data-testid="invitation-accept-errors"');
        $this->assertBearerAbsentFromPersistedSessions($token);

        $this->post('/bfc/invitations/accept', [
            'token' => $token,
            'name' => 'Session Invitee',
            'password' => 'corrected invite password',
            'password_confirmation' => 'corrected invite password',
            'intended' => '/domain',
        ])->assertRedirect('/domain');

        expect($invitation->refresh()->accepted_at)->not->toBeNull()
            ->and(User::query()->where('email', 'session-invitee@example.test')->count())->toBe(1);

        $this->post('/bfc/logout');
        $this->from($retryUrl)->post('/bfc/invitations/accept', [
            'token' => $token,
            'name' => 'Replay',
            'password' => 'another invite password',
            'password_confirmation' => 'another invite password',
            'intended' => '/domain',
        ])->assertRedirect($retryUrl)->assertSessionHasErrors(['token']);
        $this->assertBearerAbsentFromPersistedSessions($token);
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

    private function assertBearerAbsentFromPersistedSessions(string $bearer): void
    {
        $payloads = DB::table('sessions')->pluck('payload');

        $this->assertNotEmpty($payloads);

        foreach ($payloads as $payload) {
            $encoded = (string) $payload;
            $decoded = base64_decode($encoded, true);

            $this->assertIsString($decoded);
            $this->assertFalse(str_contains($encoded, $bearer), 'Bearer found in an encoded session payload.');
            $this->assertFalse(str_contains($decoded, $bearer), 'Bearer found in a decoded session payload.');
        }
    }
}
