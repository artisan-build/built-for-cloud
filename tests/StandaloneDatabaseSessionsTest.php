<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\User;
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

    private function login(User $user, string $password): void
    {
        $this->post('/bfc/login', [
            'email' => $user->email,
            'password' => $password,
        ])->assertRedirect('/');
    }
}
