<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Http\Middleware\AuthenticateMcp;
use ArtisanBuild\BuiltForCloud\Http\Middleware\AuthenticateMcpFoo;
use ArtisanBuild\BuiltForCloud\Mcp\McpConfiguration;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Route;
use Symfony\Component\Process\Process;

require_once __DIR__.'/Fixtures/AuthenticateMcpFoo.php';

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

it('recognises a parameterized package middleware alias as the exact guard class', function (): void {
    config([
        'built-for-cloud.mcp.path' => '/mcp',
        'built-for-cloud.mcp.delegated' => true,
    ]);

    Route::post('/mcp', fn (): array => ['ok' => true])->middleware('bfc.mcp:product');

    expect($this->getJson('/bfc/meta')->json('capabilities'))->toContain('mcp-delegated');
});

it('advertises effect scoping for an exact read door with no configured write path', function (): void {
    config([
        'built-for-cloud.mcp.path' => '/mcp',
        'built-for-cloud.mcp.write_path' => null,
    ]);

    Route::post('/mcp', fn (): array => ['ok' => true])
        ->middleware('bfc.mcp:product,read');

    $response = $this->getJson('/bfc/meta')->assertOk();

    expect($response->json('capabilities'))->toContain('mcp-effect-scoped')
        ->and($response->json('endpoints'))->toBe(['mcp' => '/mcp']);
});

it('advertises effect scoping and the write endpoint only for exact verified ceilings', function (): void {
    config([
        'built-for-cloud.mcp.path' => '/mcp',
        'built-for-cloud.mcp.write_path' => '/mcp-write',
    ]);

    Route::post('/mcp', fn (): array => ['ok' => true])
        ->middleware('bfc.mcp:product,read');
    Route::post('/mcp-write', fn (): array => ['ok' => true])
        ->middleware('bfc.mcp:product,write');

    $response = $this->getJson('/bfc/meta')->assertOk();

    expect($response->json('capabilities'))->toContain('mcp-effect-scoped')
        ->and($response->json('endpoints'))->toBe([
            'mcp' => '/mcp',
            'mcp_write' => '/mcp-write',
        ]);
});

it('advertises effect scoping and the destructive endpoint for an exact verified destructive ceiling', function (): void {
    config([
        'built-for-cloud.mcp.path' => '/mcp',
        'built-for-cloud.mcp.write_path' => null,
        'built-for-cloud.mcp.destructive_path' => '/mcp-destructive',
    ]);

    Route::post('/mcp', fn (): array => ['ok' => true])
        ->middleware('bfc.mcp:product,read');
    Route::post('/mcp-destructive', fn (): array => ['ok' => true])
        ->middleware('bfc.mcp:product,destructive');

    $response = $this->getJson('/bfc/meta')->assertOk();

    expect($response->json('capabilities'))->toContain('mcp-effect-scoped')
        ->and($response->json('endpoints'))->toBe([
            'mcp' => '/mcp',
            'mcp_destructive' => '/mcp-destructive',
        ]);
});

it('advertises all three verified MCP effect doors without aliasing their endpoint keys', function (): void {
    config([
        'built-for-cloud.mcp.path' => '/mcp',
        'built-for-cloud.mcp.write_path' => '/mcp-write',
        'built-for-cloud.mcp.destructive_path' => '/mcp-destructive',
    ]);

    Route::post('/mcp', fn (): array => ['ok' => true])
        ->middleware('bfc.mcp:product,read');
    Route::post('/mcp-write', fn (): array => ['ok' => true])
        ->middleware('bfc.mcp:product,write');
    Route::post('/mcp-destructive', fn (): array => ['ok' => true])
        ->middleware('bfc.mcp:product,destructive');

    $response = $this->getJson('/bfc/meta')->assertOk();

    expect($response->json('capabilities'))->toContain('mcp-effect-scoped')
        ->and($response->json('endpoints'))->toBe([
            'mcp' => '/mcp',
            'mcp_write' => '/mcp-write',
            'mcp_destructive' => '/mcp-destructive',
        ]);
});

it('fails effect scoping closed for an explicitly configured malformed write path', function (mixed $writePath): void {
    config([
        'built-for-cloud.mcp.path' => '/mcp',
        'built-for-cloud.mcp.write_path' => $writePath,
    ]);

    Route::post('/mcp', fn (): array => ['ok' => true])
        ->middleware('bfc.mcp:product,read');

    $response = $this->getJson('/bfc/meta')->assertOk();

    expect($response->json('capabilities'))->not->toContain('mcp-effect-scoped')
        ->and($response->json('endpoints'))->toBe(['mcp' => '/mcp']);
})->with([
    'empty string' => '',
    'relative path' => 'mcp-write',
    'protocol-relative path' => '//other.example.com/mcp-write',
    'query-bearing path' => '/mcp-write?mode=write',
    'non-string integer' => 1,
    'non-string array' => [['/mcp-write']],
]);

it('fails effect scoping closed for an explicitly configured malformed destructive path', function (mixed $destructivePath): void {
    config([
        'built-for-cloud.mcp.path' => '/mcp',
        'built-for-cloud.mcp.write_path' => '/mcp-write',
        'built-for-cloud.mcp.destructive_path' => $destructivePath,
    ]);

    Route::post('/mcp', fn (): array => ['ok' => true])
        ->middleware('bfc.mcp:product,read');
    Route::post('/mcp-write', fn (): array => ['ok' => true])
        ->middleware('bfc.mcp:product,write');

    $response = $this->getJson('/bfc/meta')->assertOk();

    expect($response->json('capabilities'))->not->toContain('mcp-effect-scoped')
        ->and($response->json('endpoints'))->toBe(['mcp' => '/mcp']);
})->with([
    'empty string' => '',
    'relative path' => 'mcp-destructive',
    'protocol-relative path' => '//other.example.com/mcp-destructive',
    'query-bearing path' => '/mcp-destructive?mode=destructive',
    'non-string integer' => 1,
    'non-string array' => [['/mcp-destructive']],
]);

it('does not advertise effect scoping or a destructive endpoint for the wrong ceiling', function (string $middleware): void {
    config([
        'built-for-cloud.mcp.path' => '/mcp',
        'built-for-cloud.mcp.destructive_path' => '/mcp-destructive',
    ]);

    Route::post('/mcp', fn (): array => ['ok' => true])
        ->middleware('bfc.mcp:product,read');
    Route::post('/mcp-destructive', fn (): array => ['ok' => true])
        ->middleware($middleware);

    $response = $this->getJson('/bfc/meta')->assertOk();

    expect($response->json('capabilities'))->not->toContain('mcp-effect-scoped')
        ->and($response->json('endpoints'))->toBe(['mcp' => '/mcp']);
})->with([
    'bare guard' => 'bfc.mcp',
    'read ceiling' => 'bfc.mcp:product,read',
    'write ceiling' => 'bfc.mcp:product,write',
]);

it('requires the exact product slot and parameter count on the destructive door', function (string $middleware): void {
    config([
        'built-for-cloud.mcp.path' => '/mcp',
        'built-for-cloud.mcp.destructive_path' => '/mcp-destructive',
    ]);

    Route::post('/mcp', fn (): array => ['ok' => true])
        ->middleware('bfc.mcp:product,read');
    Route::post('/mcp-destructive', fn (): array => ['ok' => true])
        ->middleware($middleware);

    $response = $this->getJson('/bfc/meta')->assertOk();

    expect($response->json('capabilities'))->not->toContain('mcp-effect-scoped')
        ->and($response->json('endpoints'))->toBe(['mcp' => '/mcp']);
})->with([
    'missing product slot' => 'bfc.mcp:destructive',
    'extra parameter' => 'bfc.mcp:product,destructive,extra',
]);

it('does not let same path verb or domain decoys certify the destructive door', function (): void {
    config([
        'built-for-cloud.mcp.path' => '/mcp',
        'built-for-cloud.mcp.destructive_path' => '/mcp-destructive',
    ]);

    Route::post('/mcp', fn (): array => ['ok' => true])
        ->middleware('bfc.mcp:product,read');
    Route::get('/mcp-destructive', fn (): array => ['ok' => true])
        ->middleware('bfc.mcp:product,destructive');
    Route::domain('other.example.com')->post('/mcp-destructive', fn (): array => ['ok' => true])
        ->middleware('bfc.mcp:product,destructive');
    Route::post('/mcp-destructive', fn (): array => ['ok' => true]);

    $response = $this->getJson('/bfc/meta')->assertOk();

    expect($response->json('capabilities'))->not->toContain('mcp-effect-scoped')
        ->and($response->json('endpoints'))->toBe(['mcp' => '/mcp']);
});

it('withholds effect scoping when a configured destructive route is absent', function (): void {
    config([
        'built-for-cloud.mcp.path' => '/mcp',
        'built-for-cloud.mcp.destructive_path' => '/mcp-destructive',
    ]);

    Route::post('/mcp', fn (): array => ['ok' => true])
        ->middleware('bfc.mcp:product,read');

    $response = $this->getJson('/bfc/meta')->assertOk();

    expect($response->json('capabilities'))->not->toContain('mcp-effect-scoped')
        ->and($response->json('endpoints'))->toBe(['mcp' => '/mcp']);
});

it('withholds the destructive endpoint when its exact guard is excluded', function (): void {
    config([
        'built-for-cloud.mcp.path' => '/mcp',
        'built-for-cloud.mcp.destructive_path' => '/mcp-destructive',
    ]);

    Route::post('/mcp', fn (): array => ['ok' => true])
        ->middleware('bfc.mcp:product,read');
    Route::post('/mcp-destructive', fn (): array => ['ok' => true])
        ->middleware('bfc.mcp:product,destructive')
        ->withoutMiddleware('bfc.mcp:product,destructive');

    $response = $this->getJson('/bfc/meta')->assertOk();

    expect($response->json('capabilities'))->not->toContain('mcp-effect-scoped')
        ->and($response->json('endpoints'))->toBe(['mcp' => '/mcp']);
});

it('never lets a destructive route earn the write endpoint', function (): void {
    config([
        'built-for-cloud.mcp.path' => '/mcp',
        'built-for-cloud.mcp.write_path' => '/mcp-destructive',
    ]);

    Route::post('/mcp', fn (): array => ['ok' => true])
        ->middleware('bfc.mcp:product,read');
    Route::post('/mcp-destructive', fn (): array => ['ok' => true])
        ->middleware('bfc.mcp:product,destructive');

    $response = $this->getJson('/bfc/meta')->assertOk();

    expect(McpConfiguration::writeEndpoint())->toBeNull()
        ->and($response->json('capabilities'))->not->toContain('mcp-effect-scoped')
        ->and($response->json('endpoints'))->toBe(['mcp' => '/mcp']);
});

it('does not advertise effect scoping or a write endpoint for the wrong middleware parameter', function (): void {
    config([
        'built-for-cloud.mcp.path' => '/mcp',
        'built-for-cloud.mcp.write_path' => '/mcp-write',
    ]);

    Route::post('/mcp', fn (): array => ['ok' => true])
        ->middleware('bfc.mcp:product,read');
    Route::post('/mcp-write', fn (): array => ['ok' => true])
        ->middleware('bfc.mcp:product,read');

    $response = $this->getJson('/bfc/meta')->assertOk();

    expect($response->json('capabilities'))->not->toContain('mcp-effect-scoped')
        ->and($response->json('endpoints'))->toBe(['mcp' => '/mcp']);
});

it('requires the exact product slot and parameter count on the write door', function (string $middleware): void {
    config([
        'built-for-cloud.mcp.path' => '/mcp',
        'built-for-cloud.mcp.write_path' => '/mcp-write',
    ]);

    Route::post('/mcp', fn (): array => ['ok' => true])
        ->middleware('bfc.mcp:product,read');
    Route::post('/mcp-write', fn (): array => ['ok' => true])
        ->middleware($middleware);

    $response = $this->getJson('/bfc/meta')->assertOk();

    expect($response->json('capabilities'))->not->toContain('mcp-effect-scoped')
        ->and($response->json('endpoints'))->toBe(['mcp' => '/mcp']);
})->with([
    'missing product slot' => 'bfc.mcp:write',
    'extra parameter' => 'bfc.mcp:product,write,extra',
]);

it('withholds effect scoping and the write endpoint unless the primary door has an exact read ceiling', function (?string $middleware): void {
    config([
        'built-for-cloud.mcp.path' => '/mcp',
        'built-for-cloud.mcp.write_path' => '/mcp-write',
    ]);

    $primary = Route::post('/mcp', fn (): array => ['ok' => true]);

    if ($middleware !== null) {
        $primary->middleware($middleware);
    }

    Route::post('/mcp-write', fn (): array => ['ok' => true])
        ->middleware('bfc.mcp:product,write');

    $response = $this->getJson('/bfc/meta')->assertOk();

    expect($response->json('capabilities'))->not->toContain('mcp-effect-scoped')
        ->and($response->json('endpoints'))->toBe(['mcp' => '/mcp']);
})->with([
    'missing guard' => null,
    'bare guard' => 'bfc.mcp',
    'missing ceiling parameter' => 'bfc.mcp:product',
    'wrong ceiling' => 'bfc.mcp:product,write',
]);

it('does not let same path verb or domain decoys certify the write door', function (): void {
    config([
        'built-for-cloud.mcp.path' => '/mcp',
        'built-for-cloud.mcp.write_path' => '/mcp-write',
    ]);

    Route::post('/mcp', fn (): array => ['ok' => true])
        ->middleware('bfc.mcp:product,read');
    Route::get('/mcp-write', fn (): array => ['ok' => true])
        ->middleware('bfc.mcp:product,write');
    Route::domain('other.example.com')->post('/mcp-write', fn (): array => ['ok' => true])
        ->middleware('bfc.mcp:product,write');
    Route::post('/mcp-write', fn (): array => ['ok' => true]);

    $response = $this->getJson('/bfc/meta')->assertOk();

    expect($response->json('capabilities'))->not->toContain('mcp-effect-scoped')
        ->and($response->json('endpoints'))->toBe(['mcp' => '/mcp']);
});

it('withholds the write endpoint when its exact guard is excluded', function (): void {
    config([
        'built-for-cloud.mcp.path' => '/mcp',
        'built-for-cloud.mcp.write_path' => '/mcp-write',
    ]);

    Route::post('/mcp', fn (): array => ['ok' => true])
        ->middleware('bfc.mcp:product,read');
    Route::post('/mcp-write', fn (): array => ['ok' => true])
        ->middleware('bfc.mcp:product,write')
        ->withoutMiddleware('bfc.mcp:product,write');

    $response = $this->getJson('/bfc/meta')->assertOk();

    expect($response->json('capabilities'))->not->toContain('mcp-effect-scoped')
        ->and($response->json('endpoints'))->toBe(['mcp' => '/mcp']);
});

it('does not recognise a different middleware class that shares the guard prefix', function (): void {
    config([
        'built-for-cloud.mcp.path' => '/mcp',
        'built-for-cloud.mcp.delegated' => true,
    ]);

    Route::post('/mcp', fn (): array => ['ok' => true])->middleware(AuthenticateMcpFoo::class.':product');

    expect($this->getJson('/bfc/meta')->json('capabilities'))->not->toContain('mcp-delegated');
});

it('reads parameterized plain and unguarded MCP routes from a real compiled route collection', function (): void {
    $payload = sys_get_temp_dir().'/bfc-mcp-metadata-route-cache-'.bin2hex(random_bytes(8)).'.php';

    try {
        $generate = new Process([PHP_BINARY, __DIR__.'/Fixtures/mcp-metadata-route-cache.php', 'generate', $payload]);
        $generate->setTimeout(60);
        $generate->mustRun();

        expect($generate->getOutput())->toContain('"contains":true');

        $load = new Process([PHP_BINARY, __DIR__.'/Fixtures/mcp-metadata-route-cache.php', 'load', $payload]);
        $load->setTimeout(60);
        $load->run();

        expect($load->getExitCode())->toBe(0, $load->getOutput().$load->getErrorOutput())
            ->and($load->getOutput())->toContain('mcp-metadata-route-cache-ok');
    } finally {
        @unlink($payload);
    }
});

it('does not count a guarded route at some other path', function (): void {
    config([
        'built-for-cloud.mcp.path' => '/mcp',
        'built-for-cloud.mcp.delegated' => true,
    ]);

    Route::post('/elsewhere', fn (): array => ['ok' => true])->middleware('bfc.mcp');

    expect($this->getJson('/bfc/meta')->json('capabilities'))->not->toContain('mcp-delegated');
});

it('does not advertise delegated MCP beside a guarded route of another verb or domain', function (): void {
    config([
        'built-for-cloud.mcp.path' => '/mcp',
        'built-for-cloud.mcp.delegated' => true,
    ]);

    // The exact shape laravel/mcp registers itself: a GET (and DELETE)
    // beside the POST transport. A guard on the decoy verb must not
    // certify the transport that actually carries the MCP session.
    Route::get('/mcp', fn (): array => ['ok' => true])->middleware('bfc.mcp');
    Route::post('/mcp', fn (): array => ['ok' => true]);

    // The coordinator reproduced the old check answering TRUE here.
    expect(McpConfiguration::delegated())->toBeFalse()
        ->and($this->getJson('/bfc/meta')->json('capabilities'))->not->toContain('mcp-delegated');

    // Same shape, across hosts: a guarded route domain-qualified to
    // another deployment shares the URI text but not this request's
    // host, so it must not stand in for the unguarded POST this host
    // would actually dispatch.
    Route::domain('other.example.com')->post('/mcp', fn (): array => ['ok' => true])->middleware('bfc.mcp');

    expect($this->getJson('/bfc/meta')->json('capabilities'))->not->toContain('mcp-delegated');
});

it('withholds delegated MCP when the guard is declared and then excluded', function (): void {
    config([
        'built-for-cloud.mcp.path' => '/mcp',
        'built-for-cloud.mcp.delegated' => true,
    ]);

    // The raw declaration carries the middleware; the EFFECTIVE
    // pipeline does not. Only the router's own gatherer sees the
    // difference, so only a check built on it withholds here.
    Route::post('/mcp', fn (): array => ['ok' => true])
        ->middleware('bfc.mcp')
        ->withoutMiddleware(AuthenticateMcp::class);

    expect($this->getJson('/bfc/meta')->json('capabilities'))->not->toContain('mcp-delegated');
});

it('earns delegated MCP for a guarded route at the root path', function (): void {
    config([
        'built-for-cloud.mcp.path' => '/',
        'built-for-cloud.mcp.delegated' => true,
    ]);

    Route::post('/', fn (): array => ['ok' => true])->middleware('bfc.mcp');

    $response = $this->getJson('/bfc/meta')->assertOk();

    expect($response->json('capabilities'))->toContain('mcp-delegated')
        ->and($response->json('endpoints'))->toBe(['mcp' => '/']);
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
