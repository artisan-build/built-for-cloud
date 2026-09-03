<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;

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

it('advertises delegated MCP only when both endpoint and delegated contract are declared', function (): void {
    config(['built-for-cloud.mcp.delegated' => true]);

    expect($this->getJson('/bfc/meta')->json('capabilities'))->not->toContain('mcp-delegated');

    config(['built-for-cloud.mcp.path' => '/mcp']);

    $response = $this->getJson('/bfc/meta')->assertOk();

    expect($response->json('capabilities'))->toContain('mcp-serve')
        ->toContain('mcp-delegated')
        ->and($response->json('endpoints'))->toBe(['mcp' => '/mcp']);
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
