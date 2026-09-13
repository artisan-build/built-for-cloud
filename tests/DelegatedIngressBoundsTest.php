<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Console\AssertionBurn;
use ArtisanBuild\BuiltForCloud\Console\AssertionRefusalReason;
use ArtisanBuild\BuiltForCloud\Console\ConsoleGuard;
use ArtisanBuild\BuiltForCloud\Console\ConsoleGuardConfiguration;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyring;
use ArtisanBuild\BuiltForCloud\Console\ConsoleSessionClock;
use ArtisanBuild\BuiltForCloud\Console\DelegatedActor;
use Carbon\CarbonImmutable;
use Illuminate\Auth\SessionGuard;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Route;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    config([
        'built-for-cloud.console.issuer' => 'https://scalpels.test',
        'built-for-cloud.console.audience' => 'https://sink.test',
    ]);
});

it('holds the issuer audience ttl and key-retirement bounds on delegated assertions', function (): void {
    $this->travelTo('2026-09-10T12:00:00+00:00');
    $secret = consoleKeypair();
    consoleFileKey('p5d-bounds-key', $secret);
    $atTtlBound = consoleMint($secret, consoleClaims([
        'exp' => now()->addSeconds(120)->toAtomString(),
    ]), 'p5d-bounds-key');
    $overTtlBound = consoleMint($secret, consoleClaims([
        'exp' => now()->addSeconds(121)->toAtomString(),
    ]), 'p5d-bounds-key');
    $wrongIssuer = consoleMint($secret, consoleClaims([
        'iss' => 'https://another-issuer.test',
    ]), 'p5d-bounds-key');

    expect(config('built-for-cloud.console.issuer'))->toBeString()
        ->not->toBeArray()
        ->and(config('built-for-cloud.console.assertion_max_ttl_seconds'))->toBe(120)
        ->and(consoleVerify($atTtlBound)->issuer)->toBe('https://scalpels.test')
        ->and(consoleRefusal($overTtlBound)->reason)->toBe(AssertionRefusalReason::TtlTooLong)
        ->and(consoleRefusal($wrongIssuer)->reason)->toBe(AssertionRefusalReason::IssuerMismatch);

    (new ConsoleKeyring)->retire('p5d-bounds-key');
    expect(consoleRefusal($atTtlBound)->reason)->toBe(AssertionRefusalReason::RetiredKey);

    config([
        'built-for-cloud.console.audience' => null,
        'app.url' => 'https://sink.test',
    ]);
    expect(fn (): mixed => consoleVerify($atTtlBound))->toThrow(RuntimeException::class);
});

it('burns an MCP assertion once and refuses a deactivated actor immediately', function (): void {
    $secret = consoleKeypair();
    consoleFileKey('p5d-mcp-key', $secret);
    Route::middleware('bfc.mcp')->post('/p5d-delegated-mcp', static fn (): array => ['accepted' => true]);
    $token = consoleMint($secret, consoleClaims([
        'purpose' => 'mcp',
        'sub' => 'p5d-delegated-operator',
        'jti' => 'p5d-mcp-first',
    ]), 'p5d-mcp-key');
    $headers = ['Authorization' => 'Bearer '.$token];

    $this->postJson('/p5d-delegated-mcp', [], $headers)->assertOk();
    $this->postJson('/p5d-delegated-mcp', [], $headers)->assertUnauthorized();
    expect(AssertionBurn::query()->count())->toBe(1);

    DelegatedActor::query()->sole()->deactivate();
    $afterDeactivation = consoleMint($secret, consoleClaims([
        'purpose' => 'mcp',
        'sub' => 'p5d-delegated-operator',
        'jti' => 'p5d-mcp-after-deactivation',
    ]), 'p5d-mcp-key');
    $this->postJson('/p5d-delegated-mcp', [], [
        'Authorization' => 'Bearer '.$afterDeactivation,
    ])->assertUnauthorized();
    expect(AssertionBurn::query()->count())->toBe(1);
});

it("uses Laravel's sliding session guard and enforces 7199 7200 rather than an 1800-second ceiling", function (): void {
    $this->travelTo('2026-09-10T12:00:00+00:00');
    Route::middleware([StartSession::class, 'bfc.console', 'auth:'.ConsoleGuardConfiguration::GUARD])
        ->get('/p5d-delegated-console', static fn (): array => ['accepted' => true]);
    $actor = consoleActor();
    $guard = auth(ConsoleGuardConfiguration::GUARD);
    $inner = new ReflectionProperty(ConsoleGuard::class, 'inner');

    expect($inner->getValue($guard))->toBeInstanceOf(SessionGuard::class)
        ->and(config('session.lifetime'))->toBeInt()
        ->and(ConsoleSessionClock::ASSERTION_AGE_CAP_MINUTES)->toBe(120);

    $this->withSession(consoleSessionState($actor, now()->getTimestamp() - 1800));
    $this->getJson('/p5d-delegated-console')->assertOk();

    $this->withSession(consoleSessionState($actor, now()->getTimestamp() - 7199));
    $this->getJson('/p5d-delegated-console')->assertOk();

    $this->withSession(consoleSessionState($actor, now()->getTimestamp() - 7200));
    $this->getJson('/p5d-delegated-console')->assertUnauthorized();
});
