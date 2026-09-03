<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Http\Middleware\AuthenticateMcp;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Route;

uses(RefreshDatabase::class);

it('advertises no MCP promise when the deployment declares no endpoint', function (): void {
    $response = $this->getJson('/bfc/meta')->assertOk();

    expect($response->json('capabilities'))->not->toContain('mcp-serve')
        ->not->toContain('mcp-delegated')
        ->and($response->json())->not->toHaveKey('endpoints');
});

it('advertises the MCP endpoint and serve capability from one path predicate', function (): void {
    config(['built-for-cloud.mcp.path' => '/mcp']);

    $this->getJson('/bfc/meta')
        ->assertOk()
        ->assertJsonPath('endpoints.mcp', '/mcp');

    $capabilities = (array) $this->getJson('/bfc/meta')->json('capabilities');

    expect($capabilities)->toContain('mcp-serve')
        ->not->toContain('mcp-delegated');
});

it('advertises delegated MCP only when the declared path is actually guarded', function (): void {
    config([
        'built-for-cloud.mcp.path' => '/mcp',
        'built-for-cloud.mcp.delegated' => true,
    ]);

    // The declaration alone, with nothing mounted at the advertised
    // path: mcp-serve still rides the path, but the stronger promise
    // is not earned by config that nothing answers for.
    expect($this->getJson('/bfc/meta')->json('capabilities'))
        ->toContain('mcp-serve')
        ->not->toContain('mcp-delegated');

    Route::post('/mcp', fn (): array => ['ok' => true])->middleware(AuthenticateMcp::class);

    $response = $this->getJson('/bfc/meta')->assertOk();

    expect($response->json('capabilities'))->toContain('mcp-serve')
        ->toContain('mcp-delegated')
        ->and($response->json('endpoints'))->toBe(['mcp' => '/mcp']);
});

it('does not advertise delegated MCP for a route the middleware does not guard', function (): void {
    config([
        'built-for-cloud.mcp.path' => '/mcp',
        'built-for-cloud.mcp.delegated' => true,
    ]);

    // A route exists at the advertised path, but something else guards
    // it: the capability and the middleware would disagree, so the
    // capability is withheld.
    Route::post('/mcp', fn (): array => ['ok' => true]);

    $response = $this->getJson('/bfc/meta')->assertOk();

    expect($response->json('capabilities'))->toContain('mcp-serve')
        ->not->toContain('mcp-delegated')
        ->and($response->json('endpoints'))->toBe(['mcp' => '/mcp']);
});

it('recognises the package middleware alias as the guard, not only the class', function (): void {
    config([
        'built-for-cloud.mcp.path' => '/mcp',
        'built-for-cloud.mcp.delegated' => true,
    ]);

    // The shape a consuming app actually writes: the alias the package
    // registers, not the class name.
    Route::post('/mcp', fn (): array => ['ok' => true])->middleware('bfc.mcp');

    expect($this->getJson('/bfc/meta')->json('capabilities'))->toContain('mcp-delegated');
});

it('does not count a guarded route at some other path', function (): void {
    config([
        'built-for-cloud.mcp.path' => '/mcp',
        'built-for-cloud.mcp.delegated' => true,
    ]);

    Route::post('/elsewhere', fn (): array => ['ok' => true])->middleware('bfc.mcp');

    expect($this->getJson('/bfc/meta')->json('capabilities'))->not->toContain('mcp-delegated');
});

it('does not advertise a malformed endpoint path', function (string $path): void {
    config([
        'built-for-cloud.mcp.path' => $path,
        'built-for-cloud.mcp.delegated' => true,
    ]);

    $response = $this->getJson('/bfc/meta')->assertOk();

    expect($response->json('capabilities'))->not->toContain('mcp-serve')
        ->not->toContain('mcp-delegated')
        ->and($response->json())->not->toHaveKey('endpoints');
})->with(['relative', '//another-host/mcp', '/mcp?query=1', "/mcp\nother"]);
