<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Console\ActingPrincipal;
use ArtisanBuild\BuiltForCloud\Console\ActingPrincipalResolver;
use ArtisanBuild\BuiltForCloud\Console\DelegatedActor;
use ArtisanBuild\BuiltForCloud\Http\Middleware\AuthenticateMcp;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\User;
use ArtisanBuild\BuiltForCloud\Tests\NoGlobalAuthMutationScan;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Route;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    config([
        'built-for-cloud.console.issuer' => 'https://scalpels.test',
        'built-for-cloud.console.audience' => 'https://sink.test',
    ]);

    Route::middleware([StartSession::class])->get('/app-route', function (Request $request): array {
        $acting = app(ActingPrincipalResolver::class)->resolve();

        return [
            'principal' => $acting->identifier(),
            'guard' => $acting->guard,
            'delegated' => $acting->delegated,
            'delegated_session_present' => $acting->delegatedSessionPresent(),
            'attribution' => $acting->attribution,
            'request_user' => $request->user()?->getAuthIdentifier(),
            'default_guard' => config('auth.defaults.guard'),
        ];
    });
});

function actingUser(bool $admin = false): User
{
    $user = User::query()->create([
        'name' => 'Local User',
        'email' => 'local@example.com',
        'password' => 'irrelevant',
    ]);

    if ($admin) {
        $user->forceFill(['role' => UserRole::Admin->value])->save();
    }

    return $user;
}

/**
 * Resolve through the real MCP middleware: a minted, MCP-purpose
 * assertion in, the value the given reader observes out.
 *
 * The middleware's `$next` must answer with a Response, so the reader's
 * value rides inside one and is decoded back out here.
 *
 * @param  Closure(Request): mixed  $read
 */
function resolveUnderMcpAssertion(string $token, Closure $read): mixed
{
    $request = Request::create('/mcp', 'POST', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$token]);

    // The resolver reads the request from the container, so the request
    // the middleware authenticates must BE the container's request —
    // exactly what a real pipeline does for the request it dispatches.
    app()->instance('request', $request);

    $response = app(AuthenticateMcp::class)->handle(
        $request,
        fn (Request $handled): JsonResponse => response()->json([
            'payload' => $read($handled),
        ]),
    );

    return json_decode($response->getContent(), true)['payload'];
}

// ─── The local resolution ───────────────────────────────────────────────────

it('resolves everything to the local user, with no delegated attribution, when only a local session is live', function (): void {
    $user = actingUser();

    // The actor exists on file; no assertion published it on this request.
    consoleActor();

    $this->actingAs($user);

    $this->getJson('/app-route')
        ->assertOk()
        ->assertJsonPath('principal', $user->getKey())
        ->assertJsonPath('guard', 'web')
        ->assertJsonPath('delegated', false)
        ->assertJsonPath('delegated_session_present', false)
        ->assertJsonPath('attribution', null)
        ->assertJsonPath('request_user', $user->getKey());
});

it('resolves nobody when no session is live and no assertion was published', function (): void {
    $this->getJson('/app-route')
        ->assertOk()
        ->assertJsonPath('principal', null)
        ->assertJsonPath('guard', null)
        ->assertJsonPath('delegated', false)
        ->assertJsonPath('attribution', null);
});

// ─── A verified request assertion is the delegated principal ────────────────

it('makes a verified request assertion the acting principal, ahead of the local session and never unioned with it', function (): void {
    actingUser();

    $token = consoleMint(consoleTestSigningKey(), consoleClaims([
        'display_name' => 'Jane Operator',
        'on_behalf_of' => 'Acme Agency',
        'purpose' => 'mcp',
    ]));

    $read = resolveUnderMcpAssertion($token, function (): array {
        $fresh = app(ActingPrincipalResolver::class)->resolve();

        return [
            'identifier' => $fresh->identifier(),
            'guard' => $fresh->guard,
            'delegated' => $fresh->delegated,
            'delegated_session_present' => $fresh->delegatedSessionPresent(),
            'attribution' => $fresh->attribution,
        ];
    });

    $actor = DelegatedActor::query()->sole();
    $qualified = 'bfc-console:'.$actor->getKey();

    expect($read['identifier'])->toBe($qualified)
        ->and($read['guard'])->toBeNull()
        ->and($read['delegated'])->toBeTrue()
        ->and($read['delegated_session_present'])->toBeTrue()
        ->and($read['attribution'])->toBe('Jane Operator (Acme Agency)');
});

it('reports a request-assertion principal on a request with no local session too', function (): void {
    $token = consoleMint(consoleTestSigningKey(), consoleClaims([
        'role' => 'member',
        'purpose' => 'mcp',
    ]));

    $read = resolveUnderMcpAssertion($token, function (): array {
        $fresh = app(ActingPrincipalResolver::class)->resolve();

        return [
            'delegated' => $fresh->delegated,
            'present' => $fresh->delegatedSessionPresent(),
            'role' => $fresh->role?->value,
        ];
    });

    expect($read['delegated'])->toBeTrue()
        ->and($read['present'])->toBeTrue()
        ->and($read['role'])->toBe('member');
});

// ─── AC28: the package mutates no global auth state ─────────────────────────

it('leaves auth.defaults.guard untouched through a request that only package code sees', function (): void {
    $user = actingUser();

    expect(config('auth.defaults.guard'))->toBe('web');

    $this->actingAs($user);

    $this->getJson('/app-route')
        ->assertOk()
        ->assertJsonPath('delegated', false)
        ->assertJsonPath('default_guard', 'web');

    expect(config('auth.defaults.guard'))->toBe('web');
});

it('never calls shouldUse, resolveUsersUsing or writes auth.defaults.guard anywhere in src/', function (): void {
    // The literal statement of AC28 as re-locked, and the one a future
    // change would trip over: any repoint is the framework's to make,
    // from its own `auth:<guard>` middleware, and this package has no
    // business touching process-global auth state itself.
    $root = dirname(__DIR__).'/src';

    // A scanner that enumerated nothing would report "clean" forever.
    expect(NoGlobalAuthMutationScan::countPhpFiles($root))->toBeGreaterThan(100)
        ->and(NoGlobalAuthMutationScan::scan($root))->toBe([]);
});

it('collects and names an offence when the walk meets one', function (): void {
    // The scan above is a claim about ABSENCE, so it is worth nothing
    // unless the WALK — not a re-implementation of it in this file — can
    // fail. This drives the same `scan()` over a fixture tree that
    // carries the offences, and the offence has to come back NAMED.
    $root = sys_get_temp_dir().'/bfc-repoint-'.bin2hex(random_bytes(6));

    mkdir($root.'/nested', 0700, true);

    $files = [
        // A real repoint, nested, so the recursion is exercised too.
        $root.'/nested/repoints.php' => "<?php\n\nfunction go(\$auth): void { \$auth->shouldUse('web'); }\n",
        // A real config write, in the other shape the scanner knows.
        $root.'/writes_config.php' => "<?php\n\nfunction go(): void { config(['auth.defaults.guard' => 'web']); }\n",
        // Prose that NAMES the offence and must not count — this file is
        // the shape of every docblock in src/ that explains why the
        // package does not repoint.
        $root.'/talks_about_it.php' => "<?php\n\n/** This does not call shouldUse() or set auth.defaults.guard' => anything. */\nfunction fine(): bool { return true; }\n",
        // A legitimate READ of the same key, which is what the resolver
        // does on every request.
        $root.'/reads_it.php' => "<?php\n\nfunction which(): mixed { return config('auth.defaults.guard'); }\n",
        // Not PHP: the walk must ignore it, so a .txt full of offences
        // cannot make the test pass for the wrong reason either.
        $root.'/notes.txt' => 'shouldUse( setDefaultDriver(',
    ];

    foreach ($files as $path => $contents) {
        file_put_contents($path, $contents);
    }

    try {
        expect(NoGlobalAuthMutationScan::countPhpFiles($root))->toBe(4)
            ->and(NoGlobalAuthMutationScan::scan($root))->toBe([
                'nested/repoints.php' => ['shouldUse'],
                'writes_config.php' => ["auth.defaults.guard' =>"],
            ]);
    } finally {
        array_map(unlink(...), array_keys($files));
        rmdir($root.'/nested');
        rmdir($root);
    }
});

it('names every mutator it knows about, and none of them in prose', function (string $code, array $expected): void {
    expect(NoGlobalAuthMutationScan::offencesIn('<?php '.$code))->toBe($expected);
})->with([
    'shouldUse' => ['$auth->shouldUse("x");', ['shouldUse']],
    'facade shouldUse' => ['Auth::shouldUse("x");', ['shouldUse']],
    'resolveUsersUsing' => ['$auth->resolveUsersUsing(fn () => null);', ['resolveUsersUsing']],
    'setDefaultDriver' => ['$auth->setDefaultDriver("x");', ['setDefaultDriver']],
    'config array write' => ["config(['auth.defaults.guard' => 'x']);", ["auth.defaults.guard' =>"]],
    'repository set' => ["\$config->set('auth.defaults.guard', 'x');", ["set('auth.defaults.guard'"]],
    'a read is not an offence' => ["\$g = config('auth.defaults.guard');", []],
    'a line comment is not an offence' => ['// never call shouldUse() here', []],
    'a docblock is not an offence' => ["/** setDefaultDriver() is the framework's job. */", []],
]);

// ─── AC24: nothing survives into the next request ───────────────────────────

it('does not carry a resolved acting principal into the next request', function (): void {
    $resolver = app(ActingPrincipalResolver::class);
    $first = $resolver->resolve();

    expect($resolver->resolve())->toBe($first);

    app()->instance('request', Request::create('/next'));

    $second = $resolver->resolve();

    expect($second)->not->toBe($first)
        ->and($second->delegatedActor)->toBeNull()
        ->and($second->identifier())->toBeNull();
});

it('does not carry a request-assertion principal into the next request', function (): void {
    $token = consoleMint(consoleTestSigningKey(), consoleClaims(['purpose' => 'mcp']));

    resolveUnderMcpAssertion($token, function (): void {
        // The request the middleware just authenticated resolves the
        // delegated actor it published.
        $inside = app(ActingPrincipalResolver::class)->resolve();

        expect($inside->delegated)->toBeTrue();
    });

    // A NEW request on the SAME application — the long-lived worker
    // case. The memo is keyed on the request instance, and the
    // assertion attribute lived on the old request object, so the
    // principal of the previous request cannot leak into this one.
    app()->instance('request', Request::create('/next'));

    $second = app(ActingPrincipalResolver::class)->resolve();

    expect($second->delegatedActor)->toBeNull()
        ->and($second->identifier())->toBeNull();
});

// ─── The VO's own shape ─────────────────────────────────────────────────────

it('never carries a delegated attribution on a non-delegated resolution', function (): void {
    $none = ActingPrincipal::none();

    expect($none->check())->toBeFalse()
        ->and($none->identifier())->toBeNull()
        ->and($none->attribution)->toBeNull()
        ->and($none->delegated)->toBeFalse()
        ->and($none->delegatedSessionPresent())->toBeFalse();

    $local = ActingPrincipal::local('web', actingUser());

    expect($local->check())->toBeTrue()
        ->and($local->attribution)->toBeNull()
        ->and($local->role)->toBeNull()
        ->and($local->onBehalfOf)->toBeNull()
        ->and($local->delegated)->toBeFalse()
        ->and($local->delegatedSessionPresent())->toBeFalse();
});

it('keeps a delegated request principal out of the local claims by construction', function (): void {
    // A delegated resolution carries role and attribution; a local one
    // cannot, structurally, so a gate branching on the role of a LOCAL
    // resolution can never admit a delegated principal's claims
    // (FLEET-C-02).
    $token = consoleMint(consoleTestSigningKey(), consoleClaims([
        'on_behalf_of' => 'Acme Agency',
        'purpose' => 'mcp',
    ]));

    $read = resolveUnderMcpAssertion($token, function (): array {
        $fresh = app(ActingPrincipalResolver::class)->resolve();

        return [
            'delegated' => $fresh->delegated,
            'present' => $fresh->delegatedSessionPresent(),
            'role' => $fresh->role?->value,
            'attribution' => $fresh->attribution,
        ];
    });

    expect($read['delegated'])->toBeTrue()
        ->and($read['present'])->toBeTrue()
        ->and($read['role'])->not->toBeNull()
        ->and($read['attribution'])->not->toBeNull();

    $local = ActingPrincipal::local('web', actingUser());

    expect($local->delegated)->toBeFalse()
        ->and($local->delegatedSessionPresent())->toBeFalse()
        ->and($local->role)->toBeNull()
        ->and($local->attribution)->toBeNull()
        ->and($local->displayName)->toBeNull()
        ->and($local->onBehalfOf)->toBeNull();
});
