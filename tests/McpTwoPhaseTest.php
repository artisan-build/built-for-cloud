<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Console\DelegatedActor;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\Mcp\AdvertisesToolEffect;
use ArtisanBuild\BuiltForCloud\Mcp\Effect;
use ArtisanBuild\BuiltForCloud\Mcp\RespectsEffectCeiling;
use ArtisanBuild\BuiltForCloud\Mcp\ToolEffect;
use ArtisanBuild\BuiltForCloud\Mcp\TwoPhase;
use ArtisanBuild\BuiltForCloud\Mcp\TwoPhaseCallTool;
use ArtisanBuild\BuiltForCloud\Mcp\TwoPhaseConfirmationRefused;
use ArtisanBuild\BuiltForCloud\Mcp\TwoPhaseConfirmationStore;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\McpDelegatedTools;
use Carbon\CarbonImmutable;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\CacheManager;
use Illuminate\Cache\Lock;
use Illuminate\Cache\Repository;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\Store;
use Illuminate\Contracts\JsonSchema\JsonSchema;
use Illuminate\Encryption\Encrypter;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Testing\TestResponse;
use Laravel\Mcp\Facades\Mcp;
use Laravel\Mcp\Request;
use Laravel\Mcp\Response;
use Laravel\Mcp\Server;
use Laravel\Mcp\Server\Tool;
use Laravel\Mcp\Server\Tools\ToolSearch;
use PHPUnit\Framework\AssertionFailedError;

uses(RefreshDatabase::class);

final class TwoPhaseProbe
{
    public static int $previews = 0;

    public static int $executions = 0;

    public static int $otherExecutions = 0;

    public static int $legacyExecutions = 0;

    /** @var array<string, mixed> */
    public static array $lastArguments = [];
}

#[ToolEffect(Effect::Destructive)]
#[TwoPhase]
final class TwoPhaseProbeTool extends Tool
{
    use AdvertisesToolEffect, RespectsEffectCeiling;

    protected string $name = 'two-phase-probe';

    /** @return array<string, mixed> */
    public function schema(JsonSchema $schema): array
    {
        return [
            'target' => $schema->string()->required(),
            'fail' => $schema->boolean(),
        ];
    }

    public function preview(Request $request): Response
    {
        $request->validate(['target' => ['required', 'string'], 'fail' => ['sometimes', 'boolean']]);
        TwoPhaseProbe::$previews++;

        return Response::json(['would_execute' => true]);
    }

    public function handle(Request $request): Response
    {
        TwoPhaseProbe::$executions++;
        TwoPhaseProbe::$lastArguments = $request->all();

        if ($request->boolean('fail')) {
            throw new RuntimeException('protected operation failed after burn');
        }

        return Response::text('executed');
    }
}

#[ToolEffect(Effect::Destructive)]
#[TwoPhase]
final class OtherTwoPhaseProbeTool extends Tool
{
    use AdvertisesToolEffect, RespectsEffectCeiling;

    protected string $name = 'other-two-phase-probe';

    public function preview(Request $request): Response
    {
        $request->validate(['target' => ['required', 'string']]);

        return Response::text('other-preview');
    }

    public function handle(): Response
    {
        TwoPhaseProbe::$otherExecutions++;

        return Response::text('other-executed');
    }
}

#[ToolEffect(Effect::Destructive)]
final class LegacyDestructiveProbeTool extends Tool
{
    use AdvertisesToolEffect, RespectsEffectCeiling;

    protected string $name = 'legacy-destructive-probe';

    public function handle(Request $request): Response
    {
        TwoPhaseProbe::$legacyExecutions++;
        TwoPhaseProbe::$lastArguments = $request->all();

        return Response::text('legacy-executed');
    }
}

final class TwoPhaseProbeServer extends Server
{
    protected array $tools = [
        TwoPhaseProbeTool::class,
        OtherTwoPhaseProbeTool::class,
        LegacyDestructiveProbeTool::class,
    ];
}

#[ToolEffect(Effect::Read)]
#[TwoPhase]
final class InvalidEffectTwoPhaseTool extends Tool
{
    use AdvertisesToolEffect, RespectsEffectCeiling;

    public function preview(): Response
    {
        return Response::text('preview');
    }

    public function handle(): Response
    {
        return Response::text('invalid');
    }
}

#[ToolEffect(Effect::Destructive)]
#[TwoPhase]
final class MissingPreviewTwoPhaseTool extends Tool
{
    use AdvertisesToolEffect, RespectsEffectCeiling;

    public function handle(): Response
    {
        return Response::text('invalid');
    }
}

#[ToolEffect(Effect::Destructive)]
#[TwoPhase]
final class ReservedConfirmTwoPhaseTool extends Tool
{
    use AdvertisesToolEffect, RespectsEffectCeiling;

    /** @return array<string, mixed> */
    public function schema(JsonSchema $schema): array
    {
        return ['confirm' => $schema->string()->required()];
    }

    public function preview(): Response
    {
        return Response::text('preview');
    }

    public function handle(): Response
    {
        return Response::text('invalid');
    }
}

#[ToolEffect(Effect::Destructive)]
final class UnmarkedConfirmTool extends Tool
{
    use AdvertisesToolEffect, RespectsEffectCeiling;

    /** @return array<string, mixed> */
    public function schema(JsonSchema $schema): array
    {
        return ['confirm' => $schema->string()->required()];
    }

    public function handle(): Response
    {
        return Response::text('unchanged');
    }
}

final class InvalidEffectTwoPhaseServer extends Server
{
    protected array $tools = [InvalidEffectTwoPhaseTool::class];
}

final class MissingPreviewTwoPhaseServer extends Server
{
    protected array $tools = [MissingPreviewTwoPhaseTool::class];
}

final class ReservedConfirmTwoPhaseServer extends Server
{
    protected array $tools = [ReservedConfirmTwoPhaseTool::class];
}

final class ToolSearchTwoPhaseServer extends Server
{
    protected array $tools = [
        ToolSearch::class => [TwoPhaseProbeTool::class],
    ];
}

/** A lock-capable test store that is not one of production's refused local drivers. */
final class TwoPhaseSharedTestStore implements LockProvider, Store
{
    private ArrayStore $values;

    /** @var array<string, array{owner: string, expires_at: int}> */
    public array $locks = [];

    /** @var (Closure(): void)|null */
    public ?Closure $afterAcquire = null;

    public bool $failForget = false;

    public function __construct()
    {
        $this->values = new ArrayStore;
    }

    public function get($key): mixed
    {
        return $this->values->get($key);
    }

    public function many(array $keys): array
    {
        return $this->values->many($keys);
    }

    public function put($key, $value, $seconds): bool
    {
        return $this->values->put($key, $value, $seconds);
    }

    public function putMany(array $values, $seconds): bool
    {
        return $this->values->putMany($values, $seconds);
    }

    public function add($key, $value, $seconds): bool
    {
        if ($this->get($key) !== null) {
            return false;
        }

        return $this->put($key, $value, $seconds);
    }

    public function increment($key, $value = 1): int|bool
    {
        return $this->values->increment($key, $value);
    }

    public function decrement($key, $value = 1): int|bool
    {
        return $this->values->decrement($key, $value);
    }

    public function forever($key, $value): bool
    {
        return $this->values->forever($key, $value);
    }

    public function touch($key, $seconds): bool
    {
        return $this->values->touch($key, $seconds);
    }

    public function forget($key): bool
    {
        if ($this->failForget) {
            return false;
        }

        return $this->values->forget($key);
    }

    public function flush(): bool
    {
        $this->locks = [];

        return $this->values->flush();
    }

    public function getPrefix(): string
    {
        return '';
    }

    public function lock($name, $seconds = 0, $owner = null): TwoPhaseSharedTestLock
    {
        return new TwoPhaseSharedTestLock($this, (string) $name, (int) $seconds, $owner);
    }

    public function restoreLock($name, $owner): TwoPhaseSharedTestLock
    {
        return $this->lock($name, 0, $owner);
    }

    public function evictBurnLocks(): void
    {
        $this->locks = [];
    }
}

final class TwoPhaseSharedTestLock extends Lock
{
    public function __construct(
        private readonly TwoPhaseSharedTestStore $store,
        string $name,
        int $seconds,
        ?string $owner = null,
    ) {
        parent::__construct($name, $seconds, $owner);
    }

    public function acquire(): bool
    {
        $existing = $this->store->locks[$this->name] ?? null;

        if ($existing !== null && $existing['expires_at'] > time()) {
            return false;
        }

        $this->store->locks[$this->name] = [
            'owner' => $this->owner,
            'expires_at' => time() + max(1, $this->seconds),
        ];

        if ($this->store->afterAcquire instanceof Closure) {
            $afterAcquire = $this->store->afterAcquire;
            $this->store->afterAcquire = null;
            $afterAcquire();
        }

        return true;
    }

    public function release(): bool
    {
        if ($this->getCurrentOwner() !== $this->owner) {
            return false;
        }

        unset($this->store->locks[$this->name]);

        return true;
    }

    protected function getCurrentOwner(): ?string
    {
        $lock = $this->store->locks[$this->name] ?? null;

        return $lock !== null && $lock['expires_at'] > time() ? $lock['owner'] : null;
    }

    public function forceRelease(): void
    {
        unset($this->store->locks[$this->name]);
    }
}

beforeEach(function (): void {
    TwoPhaseProbe::$previews = 0;
    TwoPhaseProbe::$executions = 0;
    TwoPhaseProbe::$otherExecutions = 0;
    TwoPhaseProbe::$legacyExecutions = 0;
    TwoPhaseProbe::$lastArguments = [];

    app(CacheManager::class)->extend(
        'two-phase-shared-test',
        static fn (): Repository => new Repository(new TwoPhaseSharedTestStore),
    );

    config([
        'cache.stores.two-phase-shared' => ['driver' => 'two-phase-shared-test'],
        'built-for-cloud.console.audience' => 'deployment-a',
        'built-for-cloud.mcp.two_phase.cache_store' => 'two-phase-shared',
        'built-for-cloud.mcp.two_phase.ttl_seconds' => 60,
    ]);

    Mcp::web('/two-phase', TwoPhaseProbeServer::class)
        ->middleware('bfc.mcp:product,destructive');

    foreach (['two-phase-a' => 'two-phase-secret-a', 'two-phase-b' => 'two-phase-secret-b'] as $subject => $secret) {
        Credential::query()->create([
            'kind' => CredentialKind::Bearer,
            'purpose' => CredentialPurpose::Mcp,
            'subject_type' => SubjectType::ExternalConsumer,
            'subject_ref' => $subject,
            'name' => $subject,
            'abilities' => null,
            'secret_hash' => hash('sha256', $secret),
        ]);
    }
});

/** @param array<string, mixed> $arguments */
function twoPhaseRpc(string $tool, array $arguments, string $secret = 'two-phase-secret-a', int $id = 1): TestResponse
{
    return test()->postJson('/two-phase', [
        'jsonrpc' => '2.0',
        'id' => $id,
        'method' => 'tools/call',
        'params' => ['name' => $tool, 'arguments' => $arguments],
    ], ['Authorization' => 'Bearer '.$secret]);
}

/** @param array<string, mixed> $arguments */
function twoPhasePreview(array $arguments = ['target' => 'alpha']): string
{
    $response = twoPhaseRpc('two-phase-probe', $arguments)->assertOk()
        ->assertJsonPath('result._meta.two_phase.phase', 'preview');
    $confirmation = $response->json('result._meta.two_phase.confirmation');
    expect($confirmation)->toBeString()->and(strlen($confirmation))->toBeLessThanOrEqual(512);

    return $confirmation;
}

function twoPhaseStore(): TwoPhaseConfirmationStore
{
    return app(TwoPhaseConfirmationStore::class);
}

function twoPhaseTestStore(): TwoPhaseSharedTestStore
{
    $store = Cache::store('two-phase-shared')->getStore();
    expect($store)->toBeInstanceOf(TwoPhaseSharedTestStore::class);

    return $store;
}

function twoPhaseResignWithExpiredTimestamp(string $confirmation): string
{
    [$encoded] = explode('.', $confirmation, 2);
    $json = base64_decode(strtr($encoded, '-_', '+/'), true);
    expect($json)->toBeString();
    $payload = json_decode($json, true, flags: JSON_THROW_ON_ERROR);
    $payload['exp'] = CarbonImmutable::now()->subSecond()->timestamp;
    $expired = json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    $key = hash_hmac(
        'sha256',
        'bfc:mcp:two-phase:signing:v1',
        app(Encrypter::class)->getKey(),
        true,
    );
    $signature = hash_hmac('sha256', $expired, $key, true);
    $encode = static fn (string $value): string => rtrim(strtr(base64_encode($value), '+/', '-_'), '=');

    return $encode($expired).'.'.$encode($signature);
}

function twoPhaseForgeSignature(string $confirmation): string
{
    [$payload, $encodedSignature] = explode('.', $confirmation, 2);
    $signature = base64_decode(strtr($encodedSignature, '-_', '+/'), true);
    expect($signature)->toBeString()->not->toBe('');
    $signature[0] = chr(ord($signature[0]) ^ 0x01);

    return $payload.'.'.rtrim(strtr(base64_encode($signature), '+/', '-_'), '=');
}

it('advertises the additive confirmation protocol only for marked tools', function (): void {
    $response = $this->postJson('/two-phase', [
        'jsonrpc' => '2.0',
        'id' => 1,
        'method' => 'tools/list',
        'params' => [],
    ], ['Authorization' => 'Bearer two-phase-secret-a'])->assertOk();
    $tools = collect($response->json('result.tools'))->keyBy('name');

    expect($tools['two-phase-probe']['inputSchema']['properties'])->toHaveKey('confirm')
        ->and($tools['two-phase-probe']['_meta']['two_phase'])->toBe([
            'confirmationArgument' => 'confirm',
            'protocolVersion' => 1,
        ])
        ->and($tools['legacy-destructive-probe']['inputSchema']['properties'])->not->toHaveKey('confirm')
        ->and($tools['legacy-destructive-probe']['_meta'] ?? [])->not->toHaveKey('two_phase');
});

it('previews without protected execution then burns before executing at most once', function (): void {
    $confirmation = twoPhasePreview();

    expect(TwoPhaseProbe::$previews)->toBe(1)
        ->and(TwoPhaseProbe::$executions)->toBe(0);

    twoPhaseRpc('two-phase-probe', ['target' => 'alpha', 'confirm' => $confirmation])
        ->assertOk()
        ->assertJsonPath('result._meta.two_phase.phase', 'executed')
        ->assertJsonPath('result.content.0.text', 'executed');

    twoPhaseRpc('two-phase-probe', ['target' => 'alpha', 'confirm' => $confirmation], id: 2)
        ->assertStatus(400)
        ->assertExactJson([
            'jsonrpc' => '2.0',
            'id' => 2,
            'error' => ['code' => TwoPhaseCallTool::REFUSAL_CODE, 'message' => 'confirmation_spent'],
        ]);

    expect(TwoPhaseProbe::$executions)->toBe(1)
        ->and(TwoPhaseProbe::$lastArguments)->toBe(['target' => 'alpha']);
});

it('binds confirmation to canonical arguments and accepts only object key reordering', function (): void {
    $confirmation = twoPhasePreview(['target' => 'alpha', 'fail' => false]);

    twoPhaseRpc('two-phase-probe', ['fail' => false, 'target' => 'alpha', 'confirm' => $confirmation])
        ->assertOk();

    $different = twoPhasePreview(['target' => 'alpha']);
    $response = twoPhaseRpc('two-phase-probe', ['target' => 'beta', 'confirm' => $different])
        ->assertStatus(400)
        ->assertJsonPath('error.message', 'confirmation_mismatched');

    expect($response->getContent())->not->toContain('alpha')
        ->not->toContain('beta')
        ->not->toContain($different)
        ->and(TwoPhaseProbe::$executions)->toBe(1);
});

it('distinguishes empty objects from empty lists in canonical arguments', function (): void {
    $confirmation = twoPhasePreview(['target' => 'alpha', 'scope' => (object) []]);

    twoPhaseRpc('two-phase-probe', ['target' => 'alpha', 'scope' => [], 'confirm' => $confirmation])
        ->assertStatus(400)
        ->assertExactJson([
            'jsonrpc' => '2.0',
            'id' => 1,
            'error' => ['code' => TwoPhaseCallTool::REFUSAL_CODE, 'message' => 'confirmation_mismatched'],
        ]);

    expect(TwoPhaseProbe::$executions)->toBe(0);
});

it('refuses wrong tool malformed forged and expired confirmations without protected effects', function (): void {
    $confirmation = twoPhasePreview();

    twoPhaseRpc('other-two-phase-probe', ['target' => 'alpha', 'confirm' => $confirmation])
        ->assertStatus(400)
        ->assertJsonPath('error.message', 'confirmation_mismatched');
    twoPhaseRpc('two-phase-probe', ['target' => 'alpha', 'confirm' => 'not-a-confirmation'])
        ->assertStatus(400)
        ->assertJsonPath('error.message', 'confirmation_invalid');
    twoPhaseRpc('two-phase-probe', ['target' => 'alpha', 'confirm' => twoPhaseForgeSignature($confirmation)])
        ->assertStatus(400)
        ->assertJsonPath('error.message', 'confirmation_invalid');
    twoPhaseRpc('two-phase-probe', [
        'target' => 'alpha',
        'confirm' => twoPhaseResignWithExpiredTimestamp($confirmation),
    ])->assertStatus(400)
        ->assertJsonPath('error.message', 'confirmation_expired');

    expect(TwoPhaseProbe::$executions)->toBe(0)
        ->and(TwoPhaseProbe::$otherExecutions)->toBe(0);
});

it('binds to the type-qualified delegated subject and deployment application context', function (): void {
    $subjectA = DelegatedActor::class.'#bfc-console:7';
    $subjectB = DelegatedActor::class.'#bfc-console:8';
    $minted = twoPhaseStore()->mint('two-phase-probe', '{"target":"alpha"}', $subjectA);

    expect(fn () => twoPhaseStore()->burn(
        $minted['confirmation'],
        'two-phase-probe',
        '{"target":"alpha"}',
        $subjectB,
    ))->toThrow(TwoPhaseConfirmationRefused::class, 'confirmation_mismatched');

    config(['built-for-cloud.console.audience' => 'deployment-b']);

    expect(fn () => twoPhaseStore()->burn(
        $minted['confirmation'],
        'two-phase-probe',
        '{"target":"alpha"}',
        $subjectA,
    ))->toThrow(TwoPhaseConfirmationRefused::class, 'confirmation_mismatched');

    config([
        'built-for-cloud.console.audience' => 'deployment-a',
        'built-for-cloud.manifest.slug' => 'different-app',
    ]);

    expect(fn () => twoPhaseStore()->burn(
        $minted['confirmation'],
        'two-phase-probe',
        '{"target":"alpha"}',
        $subjectA,
    ))->toThrow(TwoPhaseConfirmationRefused::class, 'confirmation_mismatched');
});

it('refuses phase two over real HTTP when the authenticated subject changes', function (): void {
    $confirmation = twoPhasePreview();

    twoPhaseRpc(
        'two-phase-probe',
        ['target' => 'alpha', 'confirm' => $confirmation],
        'two-phase-secret-b',
    )->assertStatus(400)
        ->assertExactJson([
            'jsonrpc' => '2.0',
            'id' => 1,
            'error' => ['code' => TwoPhaseCallTool::REFUSAL_CODE, 'message' => 'confirmation_mismatched'],
        ]);

    expect(TwoPhaseProbe::$executions)->toBe(0);
});

it('binds delegated phase two to the stable subject across fresh signed handoffs', function (): void {
    config(['built-for-cloud.console.issuer' => 'https://scalpels.test']);
    $key = consoleTestSigningKey();
    $assertion = static fn (string $subject): string => consoleMint($key, consoleClaims([
        'purpose' => 'mcp',
        'aud' => 'deployment-a',
        'sub' => $subject,
    ]));

    $confirmation = twoPhaseRpc(
        'two-phase-probe',
        ['target' => 'alpha'],
        $assertion('operator-a'),
    )->assertOk()
        ->assertJsonPath('result._meta.two_phase.phase', 'preview')
        ->json('result._meta.two_phase.confirmation');

    expect($confirmation)->toBeString();

    twoPhaseRpc(
        'two-phase-probe',
        ['target' => 'alpha', 'confirm' => $confirmation],
        $assertion('operator-b'),
    )->assertStatus(400)
        ->assertExactJson([
            'jsonrpc' => '2.0',
            'id' => 1,
            'error' => ['code' => TwoPhaseCallTool::REFUSAL_CODE, 'message' => 'confirmation_mismatched'],
        ]);

    expect(TwoPhaseProbe::$executions)->toBe(0);

    twoPhaseRpc(
        'two-phase-probe',
        ['target' => 'alpha', 'confirm' => $confirmation],
        $assertion('operator-a'),
    )->assertOk()
        ->assertJsonPath('result._meta.two_phase.phase', 'executed');

    expect(TwoPhaseProbe::$executions)->toBe(1);
});

it('keeps a confirmation burned when protected execution throws outcome unknown', function (): void {
    $confirmation = twoPhasePreview(['target' => 'alpha', 'fail' => true]);

    twoPhaseRpc('two-phase-probe', ['target' => 'alpha', 'fail' => true, 'confirm' => $confirmation])
        ->assertOk()
        ->assertJsonPath('result.isError', true);
    twoPhaseRpc('two-phase-probe', ['target' => 'alpha', 'fail' => true, 'confirm' => $confirmation])
        ->assertStatus(400)
        ->assertJsonPath('error.message', 'confirmation_spent');

    expect(TwoPhaseProbe::$executions)->toBe(1);
});

it('gives exactly one winner when phase two claims interleave at the atomic lock', function (): void {
    $subject = DelegatedActor::class.'#bfc-console:9';
    $arguments = '{"target":"alpha"}';
    $minted = twoPhaseStore()->mint('two-phase-probe', $arguments, $subject);
    $contender = null;
    twoPhaseTestStore()->afterAcquire = function () use ($minted, $arguments, $subject, &$contender): void {
        try {
            twoPhaseStore()->burn($minted['confirmation'], 'two-phase-probe', $arguments, $subject);
            $contender = 'won';
        } catch (TwoPhaseConfirmationRefused $refused) {
            $contender = $refused->getMessage();
        }
    };

    twoPhaseStore()->burn($minted['confirmation'], 'two-phase-probe', $arguments, $subject);

    expect($contender)->toBe('confirmation_spent');
});

it('refuses an unspent confirmation after only its mint marker is evicted', function (): void {
    $confirmation = twoPhasePreview();
    [$encodedPayload] = explode('.', $confirmation, 2);
    $json = base64_decode(strtr($encodedPayload, '-_', '+/'), true);
    expect($json)->toBeString();
    $payload = json_decode($json, true, flags: JSON_THROW_ON_ERROR);
    $context = [
        (string) config('built-for-cloud.console.audience'),
        (string) config('built-for-cloud.manifest.slug'),
    ];
    $frame = static fn (array $parts): string => implode(
        '',
        array_map(static fn (string $part): string => strlen($part).':'.$part, $parts),
    );
    $markerKey = TwoPhaseConfirmationStore::KEY_NAMESPACE
        .hash('sha256', $frame($context))
        .':mint:'.hash('sha256', $payload['id']);
    $store = twoPhaseTestStore();

    expect($store->get($markerKey))->toBeString()
        ->and($store->locks)->toBeEmpty()
        ->and($store->forget($markerKey))->toBeTrue()
        ->and($store->get($markerKey))->toBeNull()
        ->and($store->locks)->toBeEmpty();

    twoPhaseRpc('two-phase-probe', ['target' => 'alpha', 'confirm' => $confirmation], id: 2)
        ->assertStatus(400)
        ->assertExactJson([
            'jsonrpc' => '2.0',
            'id' => 2,
            'error' => ['code' => TwoPhaseCallTool::REFUSAL_CODE, 'message' => 'confirmation_spent'],
        ]);

    expect(TwoPhaseProbe::$executions)->toBe(0)
        ->and($store->locks)->toBeEmpty();
});

it('refuses a spent confirmation after only its retained burn lock is evicted', function (): void {
    $confirmation = twoPhasePreview();

    twoPhaseRpc('two-phase-probe', ['target' => 'alpha', 'confirm' => $confirmation])
        ->assertOk()
        ->assertJsonPath('result._meta.two_phase.phase', 'executed');

    twoPhaseTestStore()->evictBurnLocks();

    twoPhaseRpc('two-phase-probe', ['target' => 'alpha', 'confirm' => $confirmation], id: 2)
        ->assertStatus(400)
        ->assertExactJson([
            'jsonrpc' => '2.0',
            'id' => 2,
            'error' => ['code' => TwoPhaseCallTool::REFUSAL_CODE, 'message' => 'confirmation_spent'],
        ]);

    expect(TwoPhaseProbe::$executions)->toBe(1);
});

it('fails closed and retains the burn lock when removing the mint marker fails', function (): void {
    $confirmation = twoPhasePreview();
    $store = twoPhaseTestStore();
    $store->failForget = true;

    twoPhaseRpc('two-phase-probe', ['target' => 'alpha', 'confirm' => $confirmation])
        ->assertStatus(400)
        ->assertJsonPath('error.message', 'confirmation_unavailable');

    expect(TwoPhaseProbe::$executions)->toBe(0)
        ->and($store->locks)->toHaveCount(1);

    $store->failForget = false;

    twoPhaseRpc('two-phase-probe', ['target' => 'alpha', 'confirm' => $confirmation], id: 2)
        ->assertStatus(400)
        ->assertJsonPath('error.message', 'confirmation_spent');

    expect(TwoPhaseProbe::$executions)->toBe(0);
});

it('fails closed on process local cache and unsupported ambiguous numeric values', function (): void {
    config(['built-for-cloud.mcp.two_phase.cache_store' => null]);

    twoPhaseRpc('two-phase-probe', ['target' => 'alpha'])
        ->assertStatus(400)
        ->assertJsonPath('error.message', 'confirmation_unavailable');

    config(['built-for-cloud.mcp.two_phase.cache_store' => 'two-phase-shared']);

    twoPhaseRpc('two-phase-probe', ['target' => 'alpha', 'unsupported' => 1.5])
        ->assertStatus(400)
        ->assertJsonPath('error.message', 'confirmation_invalid');

    expect(TwoPhaseProbe::$executions)->toBe(0);
});

it('isolates sequential request state and leaves unmarked destructive tools unchanged', function (): void {
    $first = twoPhasePreview();
    $second = twoPhasePreview();

    expect($second)->not->toBe($first)
        ->and(TwoPhaseProbe::$executions)->toBe(0);

    twoPhaseRpc('legacy-destructive-probe', ['confirm' => $first])
        ->assertOk()
        ->assertJsonPath('result.content.0.text', 'legacy-executed');

    expect(TwoPhaseProbe::$legacyExecutions)->toBe(1)
        ->and(TwoPhaseProbe::$executions)->toBe(0);
});

it('conformance rejects invalid two phase declarations', function (): void {
    expect(fn () => McpDelegatedTools::assertConforms(InvalidEffectTwoPhaseServer::class))
        ->toThrow(
            AssertionFailedError::class,
            InvalidEffectTwoPhaseTool::class.' declares TwoPhase without a destructive ToolEffect.',
        )
        ->and(fn () => McpDelegatedTools::assertConforms(MissingPreviewTwoPhaseServer::class))
        ->toThrow(
            AssertionFailedError::class,
            MissingPreviewTwoPhaseTool::class.' declares TwoPhase without a public preview method.',
        );
});

it('conformance rejects two phase tools nested under ToolSearch by the real tool and bypass reason', function (): void {
    expect(fn () => McpDelegatedTools::assertConforms(ToolSearchTwoPhaseServer::class))
        ->toThrow(
            AssertionFailedError::class,
            TwoPhaseProbeTool::class.' declares TwoPhase inside a ToolSearch group, whose execute_tools path bypasses the two-phase guard.',
        );
});

it('conformance rejects a reserved confirm field declared by a marked application tool', function (): void {
    expect(fn () => McpDelegatedTools::assertConforms(ReservedConfirmTwoPhaseServer::class))
        ->toThrow(
            AssertionFailedError::class,
            ReservedConfirmTwoPhaseTool::class.' declares the reserved top-level confirm field in its application schema.',
        )
        ->and(app(UnmarkedConfirmTool::class)->toArray()['inputSchema']['properties']['confirm'])
        ->toBe(['type' => 'string'])
        ->and(app(UnmarkedConfirmTool::class)->toArray()['_meta'] ?? [])
        ->not->toHaveKey(TwoPhase::META_KEY);
});
