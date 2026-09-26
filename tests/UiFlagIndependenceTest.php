<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\Console\ActingPrincipalResolver;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureManagedAuthority;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureStandaloneAuthority;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUiAuthority;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAdmin;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAuthenticated;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\StandaloneRouteOwnership;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\PublishesDelegatedAssertion;
use ArtisanBuild\BuiltForCloud\User;
use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\View;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;

uses(RefreshDatabase::class);

afterEach(function (): void {
    CarbonImmutable::setTestNow();
});

function p5fConfigureUi(bool $enabled): void
{
    config([
        'built-for-cloud.ui.member_management' => $enabled,
        'built-for-cloud.ui.personal_credentials' => $enabled,
        'built-for-cloud.ui.installation_credentials' => $enabled,
        'built-for-cloud.ui.session_management' => $enabled,
        'built-for-cloud.ui.managed_transitions' => $enabled,
        'built-for-cloud.ui.credential_purposes' => $enabled ? ['test-created-consumption'] : [],
        'built-for-cloud.credentials.app_purposes' => $enabled ? ['test-created-consumption' => 'consumption'] : [],
    ]);
}

function p5fSetAuthority(AuthorityMode $mode): void
{
    $managed = $mode === AuthorityMode::Managed;

    DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
        'mode' => $mode->value,
        'generation' => $managed ? 7 : 1,
        'issuer' => $managed ? 'https://issuer.example.test' : null,
        'connection_id' => $managed ? 'p5f-connection' : null,
        'organization_id' => $managed ? 'p5f-organization' : null,
        'installation_id' => $managed ? 'p5f-installation' : null,
        'authority_base_url' => $managed ? 'https://authority.example.test' : null,
        'managed_connection_status' => $managed ? 'active' : null,
        'managed_connection_generation' => $managed ? 7 : null,
        'managed_connection_roster_version' => $managed ? 11 : null,
        'managed_connection_response_sequence' => $managed ? 11 : null,
    ]);
    config(['built-for-cloud.managed.client_secret' => 'test-created-client-secret']);
}

function p5fUser(string $vector, string $profile): ?User
{
    if (in_array($vector, ['unauthenticated', 'delegated'], true)) {
        return null;
    }

    $managed = in_array($vector, ['removed', 'disabled', 'stale'], true);
    $user = User::query()->create([
        'name' => 'P5f '.$vector.' '.$profile,
        'email' => "p5f-{$vector}-{$profile}@example.test",
    ]);
    $user->forceFill([
        'role' => $vector === 'unknown-role' ? 'unknown-role' : 'admin',
        'status' => $vector === 'inactive' ? 'inactive' : 'active',
        'email_verified_at' => now(),
        'original_contact_email' => $user->email,
        ...($managed ? [
            'scalpels_issuer' => 'https://issuer.example.test',
            'scalpels_connection_id' => 'p5f-connection',
            'scalpels_id' => 'p5f-'.$vector.'-'.$profile,
            'managed_membership_status' => in_array($vector, ['removed', 'disabled'], true) ? $vector : 'active',
            'managed_membership_role' => 'admin',
            'managed_membership_generation' => 7,
            'managed_membership_roster_version' => 11,
            'managed_membership_response_sequence' => 11,
            'managed_membership_responded_at' => now(),
            'membership_confirmed_at' => $vector === 'stale' ? now()->subHour() : now(),
        ] : []),
    ])->save();

    return $user->refresh();
}

/** @return array<string, int> */
function p5fEffectCounts(): array
{
    return [
        'credentials' => DB::table('credentials')->count(),
        'credential_audits' => DB::table('credential_audit_events')->count(),
        'credential_outbox' => DB::table('credential_outbox')->count(),
        'app_action_audits' => DB::table('bfc_app_action_events')->count(),
        'app_action_outbox' => DB::table('bfc_app_action_outbox')->count(),
    ];
}

/** @return array<string, mixed>|null */
function p5fProtectedUser(?User $user): ?array
{
    if (! $user instanceof User) {
        return null;
    }

    $attributes = $user->fresh()->getAttributes();

    foreach (['id', 'name', 'email', 'normalized_email', 'original_contact_email', 'scalpels_id', 'created_at', 'updated_at'] as $key) {
        unset($attributes[$key]);
    }

    return $attributes;
}

/**
 * @param  callable(): Response  $operation
 * @return array{refusal_class: string, status: int|null, location: string|null, disclosed_downstream: bool}
 */
function p5fRefusal(callable $operation): array
{
    try {
        $response = $operation();

        return [
            'refusal_class' => $response::class,
            'status' => $response->getStatusCode(),
            'location' => $response->headers->get('Location'),
            'disclosed_downstream' => str_contains((string) $response->getContent(), 'p5f-downstream-secret'),
        ];
    } catch (Throwable $exception) {
        return [
            'refusal_class' => $exception::class,
            'status' => $exception instanceof HttpExceptionInterface ? $exception->getStatusCode() : null,
            'location' => null,
            'disclosed_downstream' => str_contains($exception->getMessage(), 'p5f-downstream-secret'),
        ];
    }
}

/** @return array<string, mixed> */
function p5fHumanOutcome(bool $enabled, string $middleware, string $vector): array
{
    $profile = $enabled ? 'on' : 'off';
    p5fConfigureUi($enabled);
    p5fSetAuthority(in_array($vector, ['removed', 'disabled', 'stale'], true) ? AuthorityMode::Managed : AuthorityMode::Standalone);
    Http::fake(Http::response([], 503));
    app('auth')->forgetGuards();
    app()->forgetInstance(ActingPrincipalResolver::class);
    session()->flush();

    $user = p5fUser($vector, $profile);
    $beforeUser = p5fProtectedUser($user);
    $beforeEffects = p5fEffectCounts();
    $beforeHttp = count(Http::recorded());
    $downstream = 0;
    $uri = '/_p5f/'.strtolower(class_basename($middleware)).'/'.$vector;

    $downstreamRoute = static function () use (&$downstream): string {
        $downstream++;

        return 'p5f-downstream-secret';
    };

    if ($vector === 'delegated') {
        // The delegated vector publishes a verified request assertion on
        // the dispatched request, ahead of the gate under test.
        Route::get($uri, $downstreamRoute)
            ->middleware([PublishesDelegatedAssertion::class, $middleware]);
    } else {
        Route::get($uri, $downstreamRoute)->middleware($middleware);
    }

    $request = static function () use ($uri, $user, $vector) {
        if ($vector === 'delegated') {
            return test()->get($uri)->baseResponse;
        }

        if ($user instanceof User) {
            return test()->actingAsVersioned($user)->get($uri)->baseResponse;
        }

        return test()->get($uri)->baseResponse;
    };
    $refusal = p5fRefusal($request);
    $afterEffects = p5fEffectCounts();

    return [
        ...$refusal,
        'protected_user_before' => $beforeUser,
        'protected_user_after' => p5fProtectedUser($user),
        'audit_delivery_delta' => array_map(
            static fn (int $after, int $before): int => $after - $before,
            $afterEffects,
            $beforeEffects,
        ),
        'authority_calls' => count(Http::recorded()) - $beforeHttp,
        'downstream_invocations' => $downstream,
    ];
}

it('keeps every applicable human denial identical with all UI affordances off and on', function (string $middleware, string $vector): void {
    CarbonImmutable::setTestNow('2026-09-14T12:00:00+00:00');
    $off = p5fHumanOutcome(false, $middleware, $vector);
    $on = p5fHumanOutcome(true, $middleware, $vector);
    $expectedStatus = $middleware === EnsureUserIsAuthenticated::class
        && in_array($vector, ['unauthenticated', 'removed', 'disabled', 'stale'], true)
            ? 302
            : 403;

    expect($off)->toBe($on)
        ->and($off['status'])->toBe($expectedStatus)
        ->and($off['disclosed_downstream'])->toBeFalse()
        ->and($off['downstream_invocations'])->toBe(0)
        ->and($off['audit_delivery_delta'])->toBe([0, 0, 0, 0, 0]);
})->with([
    'authenticated gate unauthenticated' => [EnsureUserIsAuthenticated::class, 'unauthenticated'],
    'authenticated gate inactive' => [EnsureUserIsAuthenticated::class, 'inactive'],
    'authenticated gate unknown role' => [EnsureUserIsAuthenticated::class, 'unknown-role'],
    'authenticated gate delegated human' => [EnsureUserIsAuthenticated::class, 'delegated'],
    'authenticated gate removed managed human' => [EnsureUserIsAuthenticated::class, 'removed'],
    'authenticated gate disabled managed human' => [EnsureUserIsAuthenticated::class, 'disabled'],
    'authenticated gate stale managed human' => [EnsureUserIsAuthenticated::class, 'stale'],
    'admin gate unauthenticated' => [EnsureUserIsAdmin::class, 'unauthenticated'],
    'admin gate inactive' => [EnsureUserIsAdmin::class, 'inactive'],
    'admin gate unknown role' => [EnsureUserIsAdmin::class, 'unknown-role'],
    'admin gate delegated human' => [EnsureUserIsAdmin::class, 'delegated'],
    'admin gate removed managed human' => [EnsureUserIsAdmin::class, 'removed'],
    'admin gate disabled managed human' => [EnsureUserIsAdmin::class, 'disabled'],
    'admin gate stale managed human' => [EnsureUserIsAdmin::class, 'stale'],
]);

/** @return array<string, mixed> */
function p5fModeOutcome(bool $enabled, string $middleware, AuthorityMode $mode): array
{
    p5fConfigureUi($enabled);
    p5fSetAuthority($mode);
    $before = p5fEffectCounts();
    $downstream = 0;
    $request = Request::create('/_p5f/mode', 'GET');
    $refusal = p5fRefusal(static fn (): Response => app($middleware)->handle(
        $request,
        static function (Request $request) use (&$downstream): Response {
            $downstream++;

            return response('p5f-downstream-secret');
        },
    ));

    return [
        ...$refusal,
        'authority' => (array) DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->first(),
        'audit_delivery_delta' => array_map(
            static fn (int $after, int $before): int => $after - $before,
            p5fEffectCounts(),
            $before,
        ),
        'downstream_invocations' => $downstream,
    ];
}

it('keeps mode-mismatch refusals identical with all UI affordances off and on', function (string $middleware, AuthorityMode $mode): void {
    $off = p5fModeOutcome(false, $middleware, $mode);
    $on = p5fModeOutcome(true, $middleware, $mode);

    expect($off)->toBe($on)
        ->and($off['status'])->toBe(404)
        ->and($off['disclosed_downstream'])->toBeFalse()
        ->and($off['downstream_invocations'])->toBe(0)
        ->and($off['audit_delivery_delta'])->toBe([0, 0, 0, 0, 0]);
})->with([
    'standalone route in managed mode' => [EnsureStandaloneAuthority::class, AuthorityMode::Managed],
    'managed login in standalone mode' => [EnsureManagedAuthority::class, AuthorityMode::Standalone],
]);

it('keeps invalid UI authority refusal identical with all UI affordances off and on', function (): void {
    DB::unprepared('DROP TRIGGER bfc_authority_reject_delete');
    $outcomes = [];

    foreach ([false, true] as $enabled) {
        p5fConfigureUi($enabled);
        DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->delete();
        $before = p5fEffectCounts();
        $downstream = 0;
        $outcomes[] = [
            ...p5fRefusal(static fn (): Response => app(EnsureUiAuthority::class)->handle(
                Request::create('/bfc/ui', 'GET'),
                static function (Request $request) use (&$downstream): Response {
                    $downstream++;

                    return response('p5f-downstream-secret');
                },
            )),
            'authority_rows' => DB::table('bfc_authority')->count(),
            'audit_delivery_delta' => array_map(
                static fn (int $after, int $before): int => $after - $before,
                p5fEffectCounts(),
                $before,
            ),
            'downstream_invocations' => $downstream,
        ];
        DB::table('bfc_authority')->insert([
            'key' => InstallationAuthority::KEY,
            'mode' => AuthorityMode::Standalone->value,
            'generation' => 1,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    expect($outcomes[0])->toBe($outcomes[1])
        ->and($outcomes[0]['status'])->toBe(404)
        ->and($outcomes[0]['disclosed_downstream'])->toBeFalse()
        ->and($outcomes[0]['downstream_invocations'])->toBe(0)
        ->and($outcomes[0]['audit_delivery_delta'])->toBe([0, 0, 0, 0, 0]);
});

it('keeps the UI-specific intended-login branches identical with all affordances off and on', function (AuthorityMode $mode, string $route): void {
    $locations = [];
    $downstream = 0;
    View::composer('bfc::home', static function () use (&$downstream): void {
        $downstream++;
    });

    foreach ([false, true] as $enabled) {
        p5fConfigureUi($enabled);
        p5fSetAuthority($mode);
        app('auth')->forgetGuards();
        session()->flush();
        $before = p5fEffectCounts();
        $response = test()->get('/bfc/ui?test-created-section=credentials');
        $response->assertRedirect(route($route, [
            'intended' => '/bfc/ui?test-created-section=credentials',
        ]));
        $locations[] = [
            'class' => $response->baseResponse::class,
            'status' => $response->getStatusCode(),
            'location' => $response->headers->get('Location'),
            'downstream_invocations' => $downstream,
            'audit_delivery_delta' => array_map(
                static fn (int $after, int $before): int => $after - $before,
                p5fEffectCounts(),
                $before,
            ),
        ];
    }

    expect($locations[0])->toBe($locations[1])
        ->and($locations[0]['status'])->toBe(302)
        ->and($locations[0]['downstream_invocations'])->toBe(0)
        ->and($locations[0]['audit_delivery_delta'])->toBe([0, 0, 0, 0, 0]);
})->with([
    'standalone intended login' => [AuthorityMode::Standalone, 'bfc.login'],
    'managed intended login' => [AuthorityMode::Managed, 'bfc.managed.login'],
]);

/** @return array<string, mixed> */
function p5fOwnershipOutcome(bool $enabled, string $method): array
{
    p5fConfigureUi($enabled);
    $router = new Router(app('events'), app());
    $route = $router->get('/_p5f-owned', static fn (): string => 'p5f-downstream-secret')
        ->middleware(EnsureStandaloneAuthority::class)
        ->name('bfc.p5f-owned');
    $owned = [$route];
    $package = StandaloneRouteOwnership::packageMiddlewareInventory($owned);
    $action = $route->getAction();
    $action['middleware'] = [];
    $route->setAction($action);
    $before = p5fEffectCounts();

    $refusal = p5fRefusal(static function () use ($method, $router, $route, $owned, $package): Response {
        match ($method) {
            'assertOwned' => StandaloneRouteOwnership::assertOwned($router, $owned),
            'assertMatched' => StandaloneRouteOwnership::assertMatched($router, $route, $owned),
            'assertPackageMiddlewareOwned' => StandaloneRouteOwnership::assertPackageMiddlewareOwned($router, $package),
            'assertPackageMiddlewareMatched' => StandaloneRouteOwnership::assertPackageMiddlewareMatched($router, $route, $package),
        };

        return response('p5f-downstream-secret');
    });

    return [
        ...$refusal,
        'route_state' => [
            'name' => $route->getName(),
            'uri' => $route->uri(),
            'methods' => $route->methods(),
            'middleware' => $route->middleware(),
        ],
        'audit_delivery_delta' => array_map(
            static fn (int $after, int $before): int => $after - $before,
            p5fEffectCounts(),
            $before,
        ),
        'downstream_invocations' => 0,
    ];
}

it('keeps boot and match ownership refusals identical with all UI affordances off and on', function (string $method): void {
    $off = p5fOwnershipOutcome(false, $method);
    $on = p5fOwnershipOutcome(true, $method);

    expect($off)->toBe($on)
        ->and($off['refusal_class'])->toBe(RuntimeException::class)
        ->and($off['status'])->toBeNull()
        ->and($off['disclosed_downstream'])->toBeFalse()
        ->and($off['downstream_invocations'])->toBe(0)
        ->and($off['audit_delivery_delta'])->toBe([0, 0, 0, 0, 0]);
})->with([
    'owned route boot' => 'assertOwned',
    'owned route match' => 'assertMatched',
    'package middleware boot' => 'assertPackageMiddlewareOwned',
    'package middleware match' => 'assertPackageMiddlewareMatched',
]);
