<?php

declare(strict_types=1);

namespace App\Providers;

use App\Support\P6LiveState;
use ArtisanBuild\BuiltForCloud\ManagedAuthClient;
use ArtisanBuild\BuiltForCloud\ManagedFreshness;
use ArtisanBuild\BuiltForCloud\Testing\P6RuntimeCounterProof;
use ArtisanBuild\BuiltForCloud\StandaloneAccess;
use ArtisanBuild\BuiltForCloud\Testing\BoundedWait;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Foundation\Http\Events\RequestHandled;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Symfony\Component\HttpKernel\Exception\HttpException;

final class P6LiveServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app['config']->set('auth.defaults.guard', 'web');
        $this->app['config']->set('auth.guards.web', ['driver' => 'session', 'provider' => 'users']);
        $this->app['config']->set('auth.providers.users', ['driver' => 'eloquent', 'model' => User::class]);
        $this->app['config']->set('cache.default', 'database');
        $this->app['config']->set('cache.stores.database', [
            'driver' => 'database',
            'connection' => null,
            'table' => 'cache',
            'lock_connection' => null,
            'lock_table' => 'cache_locks',
        ]);
        $this->app['config']->set('session.driver', 'cookie');
        $this->app['config']->set('session.cookie', 'bfc_p6_session');
        $this->app['config']->set('queue.default', 'database');
        $this->app['config']->set('mail.default', 'array');
        $this->app['config']->set('built-for-cloud.console.enabled', true);
        $this->app['config']->set('built-for-cloud.console.issuer', 'https://p6-authority.test');
        $this->app['config']->set('built-for-cloud.console.audience', (string) env('BFC_P6_AUDIENCE'));
        $this->app['config']->set('built-for-cloud.managed.client_secret', (string) env('BFC_P6_AUTHORITY_SECRET'));
    }

    public function boot(): void
    {
        $this->app['events']->listen(RequestHandled::class, static function (RequestHandled $event): void {
            $node = (string) env('BFC_P6_NODE');
            P6LiveState::increment('node_'.$node.'_requests');
            $counter = P6RuntimeCounterProof::counterForRequest(
                $event->request->method(),
                $event->request->path(),
            );

            if (is_string($counter)) {
                P6LiveState::increment($counter.'_on_'.$node);
            }
        });

        Http::fake(function (ClientRequest $request) {
            if ($request->url() !== 'https://p6-authority.test/managed-auth/v1/memberships/confirm') {
                throw new HttpException(500, 'The local P6 authority received an unexpected request.');
            }

            P6LiveState::increment('authority_refreshes');
            P6LiveState::put('refresh_entered', 1);
            BoundedWait::until(
                static fn (): bool => P6LiveState::get('refresh_release') === 1,
                10,
                'The local P6 authority refresh barrier was not released.',
            );
            $payload = $request->data();

            return Http::response([
                'contract_version' => ManagedAuthClient::CONTRACT_VERSION,
                'issuer' => $payload['issuer'] ?? null,
                'connection_id' => $payload['connection_id'] ?? null,
                'organization_id' => $payload['organization_id'] ?? null,
                'installation_id' => $payload['installation_id'] ?? null,
                'authority_generation' => $payload['authority_generation'] ?? null,
                'scalpels_id' => $payload['scalpels_id'] ?? null,
                'membership_status' => 'active',
                'connection_status' => 'active',
                'role' => 'member',
                'roster_version' => ((int) ($payload['roster_version'] ?? 0)) + 1,
                'response_sequence' => ((int) ($payload['response_sequence'] ?? 0)) + 1,
                'responded_at' => now()->toAtomString(),
            ]);
        });

        $this->app->booted(static function (Application $app): void {
            Route::get('/_bfc-p6c/runtime', static function () use ($app): array {
                $database = (string) DB::scalar('select current_database()');
                $postgres = (string) DB::scalar('show server_version');
                $laravel = $app->version();
                $sessionIdentity = hash('sha256', implode("\0", [
                    (string) config('app.key'),
                    (string) config('session.cookie'),
                    (string) config('session.domain'),
                ]));

                return [
                    'database' => $database,
                    'laravel' => $laravel,
                    'roles' => [
                        'cache' => ['driver' => (string) config('cache.default'), 'version' => 'postgresql-'.$postgres, 'identity' => $database.':cache'],
                        'replay' => ['driver' => 'database', 'version' => 'postgresql-'.$postgres, 'identity' => $database.':console_assertion_burns'],
                        'session' => ['driver' => (string) config('session.driver'), 'version' => 'laravel-'.$laravel, 'identity' => $sessionIdentity],
                    ],
                ];
            });
            Route::get('/_bfc-p6c/state', static function (): array {
                return P6LiveState::all();
            });
            Route::post('/_bfc-p6c/barrier/release', static function (): array {
                P6LiveState::put('refresh_release', 1);

                return ['released' => true];
            });
            Route::post('/_bfc-p6c/mcp', static function (Request $request): array {
                return ['node' => (string) env('BFC_P6_NODE'), 'principal' => $request->user()?->getAuthIdentifier()];
            })->middleware(['bfc.contract-major', 'bfc.mcp']);
            Route::post('/_bfc-p6c/managed-refresh/{user}', static function (User $user): array {
                return ['allowed' => app(ManagedFreshness::class)->allows($user)];
            });
            Route::get('/_bfc-p6c/session', static function (Request $request): array {
                return ['user_id' => $request->user()?->getAuthIdentifier(), 'node' => (string) env('BFC_P6_NODE')];
            })->middleware(['web', 'bfc.auth']);
            Route::post('/_bfc-p6c/session/invalidate', static function (Request $request): array {
                $user = $request->user();
                abort_unless($user instanceof User, 401);
                StandaloneAccess::invalidateSessions($user);

                return ['invalidated' => true];
            })->middleware(['web', 'bfc.auth'])->withoutMiddleware(PreventRequestForgery::class);
        });
    }
}
