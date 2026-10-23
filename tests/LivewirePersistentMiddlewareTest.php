<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use ArtisanBuild\BuiltForCloud\Http\Middleware\AuthenticateMcp;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureContractMajor;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAbility;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureStandaloneAuthority;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAdmin;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAuthenticated;
use ArtisanBuild\BuiltForCloud\Http\Middleware\VerifyHmacSignature;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\PersistentMiddlewareComponent;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Route;
use Livewire\Drawer\Utils;
use Livewire\Livewire;
use Livewire\LivewireServiceProvider;

final class LivewirePersistentMiddlewareTest extends TestCase
{
    use RefreshDatabase;

    /**
     * @param  Application  $app
     * @return list<class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [LivewireServiceProvider::class, BuiltForCloudServiceProvider::class];
    }

    public function test_every_bfc_route_middleware_is_registered_as_livewire_persistent_middleware(): void
    {
        $persistent = Livewire::getPersistentMiddleware();

        foreach ([
            EnsureUserIsAuthenticated::class,
            EnsureContractMajor::class,
            EnsureUserIsAdmin::class,
            EnsureCredentialAdmin::class,
            EnsureCredentialAbility::class,
            VerifyHmacSignature::class,
            AuthenticateMcp::class,
            EnsureStandaloneAuthority::class,
        ] as $middleware) {
            $this->assertContains($middleware, $persistent);
        }
    }

    public function test_bfc_auth_refuses_a_livewire_update_after_its_session_is_removed(): void
    {
        $snapshot = $this->renderAuthenticatedComponent();

        auth()->logout();
        $this->flushSession();

        $this->postJson(Livewire::getUpdateUri(), $this->updatePayload($snapshot), [
            'X-Livewire' => 'true',
        ])->assertUnauthorized();
    }

    public function test_bfc_auth_allows_a_livewire_update_with_a_valid_session(): void
    {
        $snapshot = $this->renderAuthenticatedComponent();

        $response = $this->postJson(Livewire::getUpdateUri(), $this->updatePayload($snapshot), [
            'X-Livewire' => 'true',
        ])->assertOk();

        $this->assertStringContainsString(
            '>1</div>',
            (string) $response->json('components.0.effects.html'),
        );
    }

    private function renderAuthenticatedComponent(): string
    {
        Route::livewire('/persistent-middleware', PersistentMiddlewareComponent::class)
            ->middleware(['web', 'bfc.auth']);

        $user = User::query()->create([
            'name' => 'Persistent middleware user',
            'email' => 'persistent-middleware@example.test',
            'password' => Hash::make('test-created-password'),
        ]);
        $user->forceFill([
            'role' => UserRole::Member->value,
            'status' => 'active',
            'email_verified_at' => now(),
        ])->save();

        $response = $this->actingAsVersioned($user)->get('/persistent-middleware');
        $response->assertOk();

        return json_encode(
            Utils::extractAttributeDataFromHtml((string) $response->getContent(), 'wire:snapshot'),
            JSON_THROW_ON_ERROR,
        );
    }

    /** @return array{components: list<array{snapshot: string, updates: array<never, never>, calls: list<array{method: string, params: array<never, never>, path: string}>}>} */
    private function updatePayload(string $snapshot): array
    {
        return [
            'components' => [[
                'snapshot' => $snapshot,
                'updates' => [],
                'calls' => [[
                    'method' => 'increment',
                    'params' => [],
                    'path' => '',
                ]],
            ]],
        ];
    }
}
