<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\Http\Middleware\AuthenticateMcp;
use ArtisanBuild\BuiltForCloud\Mcp\Effect;
use ArtisanBuild\BuiltForCloud\Mcp\RequestEffectCeiling;
use ArtisanBuild\BuiltForCloud\Mcp\RespectsEffectCeiling;
use ArtisanBuild\BuiltForCloud\Mcp\ToolEffect;
use ArtisanBuild\BuiltForCloud\SubjectType;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Testing\TestResponse;
use Laravel\Mcp\Facades\Mcp;
use Laravel\Mcp\Response;
use Laravel\Mcp\Server;
use Laravel\Mcp\Server\Tool;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;

uses(RefreshDatabase::class);

final class EffectCeilingProbe
{
    public static int $readCalls = 0;

    public static int $writeCalls = 0;

    public static int $disabledWriteCalls = 0;

    public static int $undeclaredCalls = 0;
}

#[ToolEffect(Effect::Read)]
final class CeilingReadTool extends Tool
{
    use RespectsEffectCeiling;

    protected string $name = 'ceiling-read';

    public function handle(): Response
    {
        EffectCeilingProbe::$readCalls++;

        return Response::text('read-called');
    }
}

#[ToolEffect(Effect::Write)]
final class CeilingWriteTool extends Tool
{
    use RespectsEffectCeiling;

    protected string $name = 'ceiling-write';

    public function handle(): Response
    {
        EffectCeilingProbe::$writeCalls++;

        return Response::text('write-called');
    }
}

#[ToolEffect(Effect::Write)]
final class CeilingDisabledWriteTool extends Tool
{
    use RespectsEffectCeiling;

    protected string $name = 'ceiling-disabled-write';

    public function shouldRegister(): bool
    {
        return false;
    }

    public function handle(): Response
    {
        EffectCeilingProbe::$disabledWriteCalls++;

        return Response::text('disabled-write-called');
    }
}

final class CeilingUndeclaredTool extends Tool
{
    use RespectsEffectCeiling;

    protected string $name = 'ceiling-undeclared';

    public function handle(): Response
    {
        EffectCeilingProbe::$undeclaredCalls++;

        return Response::text('undeclared-called');
    }
}

final class EffectCeilingServer extends Server
{
    protected array $tools = [
        CeilingReadTool::class,
        CeilingWriteTool::class,
        CeilingDisabledWriteTool::class,
        CeilingUndeclaredTool::class,
    ];
}

final class PublishStaleEffectCeiling
{
    /** @param Closure(Request): SymfonyResponse $next */
    public function handle(Request $request, Closure $next): SymfonyResponse
    {
        RequestEffectCeiling::publish($request, Effect::Write->value);

        return $next($request);
    }
}

beforeEach(function (): void {
    EffectCeilingProbe::$readCalls = 0;
    EffectCeilingProbe::$writeCalls = 0;
    EffectCeilingProbe::$disabledWriteCalls = 0;
    EffectCeilingProbe::$undeclaredCalls = 0;

    Mcp::web('/effect/read', EffectCeilingServer::class)
        ->middleware('bfc.mcp:product,read');
    Mcp::web('/effect/write', EffectCeilingServer::class)
        ->middleware('bfc.mcp:product,write');
    Mcp::web('/effect/destructive', EffectCeilingServer::class)
        ->middleware('bfc.mcp:product,destructive');
    Mcp::web('/effect/missing', EffectCeilingServer::class)
        ->middleware('bfc.mcp:product');
    Mcp::web('/effect/invalid', EffectCeilingServer::class)
        ->middleware('bfc.mcp:product,invalid');
    Mcp::web('/effect/stale', EffectCeilingServer::class)
        ->middleware([PublishStaleEffectCeiling::class, 'bfc.mcp:product']);

    Credential::query()->create([
        'kind' => CredentialKind::Bearer,
        'purpose' => CredentialPurpose::Mcp,
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'effect-ceiling-test',
        'name' => 'effect ceiling test',
        'abilities' => null,
        'secret_hash' => hash('sha256', 'effect-ceiling-secret'),
    ]);
});

/**
 * @param  array<string, mixed>  $params
 */
function effectCeilingRpc(string $path, string $method, array $params = [], int|string $id = 1): TestResponse
{
    return test()->postJson($path, [
        'jsonrpc' => '2.0',
        'id' => $id,
        'method' => $method,
        'params' => $params,
    ], [
        'Authorization' => 'Bearer effect-ceiling-secret',
    ]);
}

it('neither lists nor calls a write tool through the read door', function (): void {
    $listed = effectCeilingRpc('/effect/read', 'tools/list')->assertOk();

    expect(array_column($listed->json('result.tools'), 'name'))
        ->toBe(['ceiling-read']);

    effectCeilingRpc('/effect/read', 'tools/call', [
        'name' => 'ceiling-write',
        'arguments' => [],
    ])->assertStatus(400)
        ->assertExactJson([
            'jsonrpc' => '2.0',
            'id' => 1,
            'error' => [
                'code' => RequestEffectCeiling::REFUSAL_CODE,
                'message' => RequestEffectCeiling::REFUSAL_MESSAGE,
            ],
        ]);

    expect(EffectCeilingProbe::$writeCalls)->toBe(0);
});

it('refuses an oversized id at the product door before the tool executes', function (): void {
    $maximumId = str_repeat('x', AuthenticateMcp::MAX_JSON_RPC_ID_BYTES - 2);
    $oversizedId = $maximumId.'x';

    effectCeilingRpc('/effect/read', 'tools/call', [
        'name' => 'ceiling-read',
        'arguments' => [],
    ], $oversizedId)->assertStatus(400)
        ->assertExactJson([
            'jsonrpc' => '2.0',
            'id' => null,
            'error' => [
                'code' => -32600,
                'message' => 'Invalid Request',
            ],
        ]);

    expect(EffectCeilingProbe::$readCalls)->toBe(0);

    effectCeilingRpc('/effect/read', 'tools/call', [
        'name' => 'ceiling-read',
        'arguments' => [],
    ], $maximumId)->assertOk()
        ->assertJsonPath('id', $maximumId)
        ->assertJsonPath('result.content.0.text', 'read-called');

    expect(EffectCeilingProbe::$readCalls)->toBe(1);
});

it('leaves write tools unreachable and metadata understated without a valid write door', function (): void {
    config([
        'built-for-cloud.mcp.path' => '/effect/read',
        'built-for-cloud.mcp.write_path' => '/effect/missing',
    ]);

    effectCeilingRpc('/effect/read', 'tools/call', [
        'name' => 'ceiling-write',
        'arguments' => [],
    ])->assertStatus(400)
        ->assertJsonPath('error.message', 'effect_above_ceiling');

    $metadata = $this->getJson('/bfc/meta')->assertOk();

    expect($metadata->json('capabilities'))->not->toContain('mcp-effect-scoped')
        ->and($metadata->json('endpoints'))->toBe(['mcp' => '/effect/read'])
        ->and(EffectCeilingProbe::$writeCalls)->toBe(0);
});

it('calls a read tool through both read and higher effect doors', function (): void {
    foreach (['/effect/read', '/effect/write'] as $path) {
        effectCeilingRpc($path, 'tools/call', [
            'name' => 'ceiling-read',
            'arguments' => [],
        ])->assertOk()
            ->assertJsonPath('result.content.0.text', 'read-called');
    }

    expect(EffectCeilingProbe::$readCalls)->toBe(2);
});

it('treats an undeclared tool as destructive rather than read', function (): void {
    $readList = effectCeilingRpc('/effect/read', 'tools/list')->assertOk();
    $destructiveList = effectCeilingRpc('/effect/destructive', 'tools/list')->assertOk();

    expect(array_column($readList->json('result.tools'), 'name'))
        ->not->toContain('ceiling-undeclared')
        ->and(array_column($destructiveList->json('result.tools'), 'name'))
        ->toContain('ceiling-undeclared');
});

it('distinguishes an above ceiling refusal from a genuinely absent tool', function (): void {
    $above = effectCeilingRpc('/effect/read', 'tools/call', [
        'name' => 'ceiling-write',
        'arguments' => [],
    ])->assertStatus(400);
    $absent = effectCeilingRpc('/effect/read', 'tools/call', [
        'name' => 'does-not-exist',
        'arguments' => [],
    ], 2)->assertStatus(400);

    expect($above->json('error.message'))->toBe('effect_above_ceiling')
        ->and($above->json('error.code'))->toBe(RequestEffectCeiling::REFUSAL_CODE)
        ->and($absent->json('error.message'))->toBe('Tool [does-not-exist] not found.')
        ->and($absent->json('error.code'))->toBe(-32602);
});

it('preserves a false registration predicate before applying the effect ceiling', function (): void {
    $listed = effectCeilingRpc('/effect/read', 'tools/list')->assertOk();
    $absent = effectCeilingRpc('/effect/read', 'tools/call', [
        'name' => 'ceiling-disabled-write',
        'arguments' => [],
    ])->assertStatus(400);

    expect(array_column($listed->json('result.tools'), 'name'))
        ->not->toContain('ceiling-disabled-write')
        ->and($absent->json('error.message'))->toBe('Tool [ceiling-disabled-write] not found.')
        ->and($absent->json('error.code'))->toBe(-32602)
        ->and(EffectCeilingProbe::$disabledWriteCalls)->toBe(0);
});

it('fails closed for missing invalid stale and cross request ceiling state', function (): void {
    effectCeilingRpc('/effect/write', 'tools/call', [
        'name' => 'ceiling-write',
        'arguments' => [],
    ])->assertOk();

    effectCeilingRpc('/effect/missing', 'tools/list')
        ->assertOk()
        ->assertJsonPath('result.tools', []);
    effectCeilingRpc('/effect/missing', 'tools/call', [
        'name' => 'ceiling-read',
        'arguments' => [],
    ])->assertStatus(400)
        ->assertJsonPath('error.message', 'effect_above_ceiling');
    effectCeilingRpc('/effect/invalid', 'tools/list')
        ->assertOk()
        ->assertJsonPath('result.tools', []);
    effectCeilingRpc('/effect/stale', 'tools/list')
        ->assertOk()
        ->assertJsonPath('result.tools', []);

    expect(EffectCeilingProbe::$writeCalls)->toBe(1)
        ->and(EffectCeilingProbe::$readCalls)->toBe(0);
});
