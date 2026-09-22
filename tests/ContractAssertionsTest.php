<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureStandaloneAuthority;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureUserIsAuthenticated;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\RouteMiddleware;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\ContractAssertions;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\AssertionFailedError;

uses(RefreshDatabase::class);
uses(ContractAssertions::class);

beforeEach(function (): void {
    Queue::fake();
});

it('passes the reusable built for cloud contract suite against the package harness', function (): void {
    $this->assertBuiltForCloudContract();
});

it('drives the public credential listing conformance assertion in package', function (): void {
    $this->assertBuiltForCloudCredentialListingContract();
});

it('accepts parameterized aliases in the reusable human lifecycle middleware assertions', function (): void {
    $login = Route::getRoutes()->getByName('bfc.login.store');
    $account = Route::getRoutes()->getByName('bfc.sessions.index');

    expect($login)->not->toBeNull()
        ->and($account)->not->toBeNull();

    foreach ([
        [$login, EnsureStandaloneAuthority::class, 'bfc.standalone:product'],
        [$account, EnsureUserIsAuthenticated::class, 'bfc.auth:'.EnsureUserIsAuthenticated::DEFER_MANAGED_AUTHORITY],
    ] as [$route, $class, $alias]) {
        $action = $route->getAction();
        $middleware = (array) ($action['middleware'] ?? []);

        expect(RouteMiddleware::indexOfClass($middleware, $class))->not->toBeNull();

        $action['middleware'] = array_map(
            static fn (string $entry): string => explode(':', $entry, 2)[0] === $class ? $alias : $entry,
            $middleware,
        );
        $route->setAction($action);
    }

    $this->assertBuiltForCloudHumanLifecycleContract();
});

it('preserves the public token helpers on the unified credential store', function (): void {
    $adminMethod = implode('', ['mintBuiltForCloud', 'Admin', 'Token']);
    $consumeMethod = implode('', ['mintBuiltForCloud', 'Consume', 'Token']);
    $admin = $this->{$adminMethod}();
    $consume = $this->{$consumeMethod}();

    $adminCredential = Credential::query()->where('secret_hash', hash('sha256', $admin))->firstOrFail();
    $consumeCredential = Credential::query()->where('secret_hash', hash('sha256', $consume))->firstOrFail();

    expect($adminCredential->subject_type)->toBe(SubjectType::Operator)
        ->and($adminCredential->abilities)->toBe([OperatorAbility::Admin->value])
        ->and($consumeCredential->subject_type)->toBe(SubjectType::ExternalConsumer)
        ->and($consumeCredential->abilities)->toBeNull();
});

it('exercises the consumer thin-host conformance wrapper', function (): void {
    $this->assertBuiltForCloudThinHostSources(__DIR__.'/Fixtures/ThinHost');

    expect(fn () => $this->assertBuiltForCloudThinHostSources(__DIR__.'/Fixtures/RogueHost'))
        ->toThrow(AssertionFailedError::class);
});

it('accepts a manifest matching the canonical catalog entry exactly', function (): void {
    $catalogEntry = [
        'name' => 'Catalog Test App',
        'slug' => 'catalog-test-app',
        'description' => 'A test-created catalog description.',
        'icon' => 'https://assets.example.test/catalog-test-app.svg',
        'product_url' => 'https://scalpels.app/products/catalog-test-app',
    ];
    config(['built-for-cloud.manifest' => $catalogEntry]);

    $this->assertBuiltForCloudManifestMatches($catalogEntry);
    expect(true)->toBeTrue();
});

it('refuses an independent catalog mismatch for every manifest field', function (string $field): void {
    $catalogEntry = [
        'name' => 'Catalog Test App',
        'slug' => 'catalog-test-app',
        'description' => 'A test-created catalog description.',
        'icon' => 'https://assets.example.test/catalog-test-app.svg',
        'product_url' => 'https://scalpels.app/products/catalog-test-app',
    ];
    $manifest = $catalogEntry;
    $manifest[$field] = 'independent mismatch for '.$field;
    config(['built-for-cloud.manifest' => $manifest]);

    expect(fn () => $this->assertBuiltForCloudManifestMatches($catalogEntry))
        ->toThrow(AssertionFailedError::class, "manifest [{$field}]");
})->with(['name', 'slug', 'description', 'icon', 'product_url']);
