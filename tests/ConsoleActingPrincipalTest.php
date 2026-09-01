<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Console\ActingPrincipal;
use ArtisanBuild\BuiltForCloud\Console\ActingPrincipalResolver;
use ArtisanBuild\BuiltForCloud\Console\ConsoleGuard;
use ArtisanBuild\BuiltForCloud\Console\ConsoleGuardConfiguration;
use ArtisanBuild\BuiltForCloud\Console\ConsoleReentryReason;
use ArtisanBuild\BuiltForCloud\Console\ConsoleRole;
use ArtisanBuild\BuiltForCloud\Console\DelegatedActor;
use ArtisanBuild\BuiltForCloud\Console\DelegatedClaims;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\User;
use ArtisanBuild\BuiltForCloud\Tests\NoGlobalAuthMutationScan;
use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Route;

uses(RefreshDatabase::class);

/**
 * D14 conformance, on the design the ruling of 2026-08-29 settled: the
 * delegated actor wins because THE ROUTE'S GUARD IS THE CONSOLE GUARD,
 * not because anything was repointed behind the framework's back.
 *
 * `/console-route` carries the production stack — `bfc.console` for the
 * structured re-entry answer, then Laravel's own `auth:bfc-console`,
 * which is what makes the console guard the guard of that request. It
 * performs the two reads that will exist in production as separate
 * consumers — the acting principal (PR4's endpoint, PR7's audit) and the
 * chrome branch (PR5's layout) — and reports whether they got the SAME
 * object, not merely two answers that happen to agree. Equal answers
 * would pass a weaker test while still permitting exactly the drift D14
 * forbids.
 *
 * `/app-route` is the app's own `web`-guarded route, where the acting
 * principal is the app's own user: the honest boundary of what a package
 * can say about a stack it does not own.
 */
beforeEach(function (): void {
    Gate::define('bfc-console-probe', fn ($user): bool => $user instanceof DelegatedActor);

    Route::middleware([StartSession::class, 'bfc.console', 'auth:'.ConsoleGuardConfiguration::GUARD])
        ->get('/console-route', function (Request $request): array {
            // The acting-principal read.
            $forPrincipal = app(ActingPrincipalResolver::class)->resolve();

            // The chrome/attribution read, made independently, as a
            // layout in another file would make it.
            $forChrome = app(ActingPrincipalResolver::class)->resolve();

            return [
                'principal' => $forPrincipal->identifier(),
                'guard' => $forPrincipal->guard,
                'delegated' => $forChrome->delegated,
                'attribution' => $forChrome->attribution,
                'role' => $forChrome->role?->value,
                'on_behalf_of' => $forChrome->onBehalfOf,
                'same_resolution' => $forPrincipal === $forChrome,
                'principal_object' => spl_object_id($forPrincipal),
                'chrome_object' => spl_object_id($forChrome),
                // The three readers AC22 names.
                'request_user' => $request->user()?->getAuthIdentifier(),
                'auth_user' => Auth::user()?->getAuthIdentifier(),
                'auth_id' => Auth::id(),
                // Gate resolves its user through the route's guard too.
                'gate_sees_delegated' => Gate::allows('bfc-console-probe'),
                // Not merely equal answers: the same instance.
                'one_object' => $request->user() === $forPrincipal->principal
                    && Auth::user() === $forPrincipal->principal,
                // Proof a local session really is live on this request.
                'local_session_user' => auth('web')->id(),
            ];
        });

    Route::middleware([StartSession::class])->get('/app-route', function (Request $request): array {
        $acting = app(ActingPrincipalResolver::class)->resolve();

        return [
            'principal' => $acting->identifier(),
            'guard' => $acting->guard,
            'delegated' => $acting->delegated,
            'delegated_session_present' => $acting->delegatedSessionPresent(),
            'attribution' => $acting->attribution,
            'request_user' => $request->user()?->getAuthIdentifier(),
            'auth_user' => Auth::user()?->getAuthIdentifier(),
            'default_guard' => config('auth.defaults.guard'),
            'refused' => $acting->wasRefused(),
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
        $user->forceFill(['is_admin' => true])->save();
    }

    return $user;
}

// ─── AC22 + AC4: one principal, seen identically by every reader ────────────

it('makes the delegated actor the principal every reader sees on a console-guarded route', function (): void {
    $user = actingUser();
    $actor = consoleActor(displayName: 'Jane Operator', role: ConsoleRole::Admin, onBehalfOf: 'Acme Agency');

    $this->actingAs($user)->withSession(consoleSessionState($actor));

    $qualified = 'bfc-console:'.$actor->getKey();

    $response = $this->getJson('/console-route')->assertOk();

    // Both sessions were genuinely live on this request.
    expect($response->json('local_session_user'))->toBe($user->getKey());

    $response
        ->assertJsonPath('principal', $qualified)
        ->assertJsonPath('guard', 'bfc-console')
        ->assertJsonPath('delegated', true)
        ->assertJsonPath('attribution', 'Jane Operator (Acme Agency)')
        ->assertJsonPath('role', 'admin')
        ->assertJsonPath('on_behalf_of', 'Acme Agency')
        // AC22's three readers, and the resolver, all the same object.
        ->assertJsonPath('request_user', $qualified)
        ->assertJsonPath('auth_user', $qualified)
        ->assertJsonPath('auth_id', $qualified)
        ->assertJsonPath('gate_sees_delegated', true)
        ->assertJsonPath('one_object', true)
        // The whole point of D14: ONE resolution, read twice.
        ->assertJsonPath('same_resolution', true);

    expect($response->json('principal_object'))->toBe($response->json('chrome_object'));
});

// ─── AC5: the reverse ───────────────────────────────────────────────────────

it('resolves everything to the local user, with no delegated attribution, when only a local session is live', function (): void {
    $user = actingUser();

    // The actor exists on file; it simply is not in this session.
    consoleActor();

    $this->actingAs($user);

    $this->getJson('/app-route')
        ->assertOk()
        ->assertJsonPath('principal', $user->getKey())
        ->assertJsonPath('guard', 'web')
        ->assertJsonPath('delegated', false)
        ->assertJsonPath('delegated_session_present', false)
        ->assertJsonPath('attribution', null)
        ->assertJsonPath('request_user', $user->getKey())
        ->assertJsonPath('auth_user', $user->getKey());
});

it('resolves nobody when neither session is live', function (): void {
    $this->getJson('/app-route')
        ->assertOk()
        ->assertJsonPath('principal', null)
        ->assertJsonPath('guard', null)
        ->assertJsonPath('delegated', false)
        ->assertJsonPath('attribution', null);
});

// ─── AC28: the package mutates no global auth state ─────────────────────────

it('leaves auth.defaults.guard untouched through a request that only package code sees', function (): void {
    $user = actingUser();
    $actor = consoleActor();

    expect(config('auth.defaults.guard'))->toBe('web');

    $this->actingAs($user)->withSession(consoleSessionState($actor));

    // A live delegated session, the resolver consulted, the console
    // guard read (and therefore its clock enforced) — and the
    // application's default guard is exactly where the app left it. The
    // old design repointed it here and needed a terminating callback to
    // put it back; there is nothing to put back now.
    $this->getJson('/app-route')
        ->assertOk()
        ->assertJsonPath('delegated', false)
        ->assertJsonPath('delegated_session_present', true)
        ->assertJsonPath('default_guard', 'web');

    expect(config('auth.defaults.guard'))->toBe('web');
});

it('never calls shouldUse, resolveUsersUsing or writes auth.defaults.guard anywhere in src/', function (): void {
    // The literal statement of AC28 as re-locked, and the one a future
    // change would trip over: the repoint is the framework's to make,
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
        $root.'/nested/repoints.php' => "<?php\n\nfunction go(\$auth): void { \$auth->shouldUse('bfc-console'); }\n",
        // A real config write, in the other shape the scanner knows.
        $root.'/writes_config.php' => "<?php\n\nfunction go(): void { config(['auth.defaults.guard' => 'bfc-console']); }\n",
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

it('resolves a subsequent non-console request normally after a delegated one', function (): void {
    $user = actingUser();
    $actor = consoleActor();

    $this->actingAs($user)->withSession(consoleSessionState($actor));

    $this->getJson('/console-route')
        ->assertOk()
        ->assertJsonPath('delegated', true);

    // The framework's own `auth:bfc-console` set the default guard for
    // the request it ran in, exactly as `auth:api` would on any Laravel
    // app. A real deployment rebuilds all userland state at request
    // shutdown (PHP-FPM — the worker persists, the PHP state does not)
    // or installs a fresh config clone (Octane), so that boundary is
    // simulated here. The MECHANISM is not simulated away in
    // tests/ConsoleGuardScopingTest.php, which asserts both that the
    // leak is real without a config sandbox and that the clone is what
    // closes it.
    config(['auth.defaults.guard' => 'web']);
    Auth::forgetGuards();

    $this->actingAs($user);

    // "Resolves normally" means through the app's OWN guard: the local
    // user is the principal, and the delegated session that is still in
    // this browser's session is reported rather than substituted.
    $this->getJson('/app-route')
        ->assertOk()
        ->assertJsonPath('principal', $user->getKey())
        ->assertJsonPath('guard', 'web')
        ->assertJsonPath('delegated', false)
        ->assertJsonPath('request_user', $user->getKey())
        ->assertJsonPath('auth_user', $user->getKey())
        ->assertJsonPath('default_guard', 'web');
})->note('AC28 as originally worded could not hold for ANY design in which Auth::user() returns the delegated actor: Auth::user() is by definition the default guard\'s user, and Laravel\'s own Authenticate middleware writes auth.defaults.guard via shouldUse(). Ed ruled 2026-08-29 to keep the stock middleware. What this package guarantees, and what the test above pins, is that it makes no such write itself; what keeps the framework\'s write from outliving the request is the runtime\'s config sandboxing, asserted in ConsoleGuardScopingTest.');

// ─── AC24: nothing survives into the next request ───────────────────────────

it('never returns a principal resolved in one request in the next one', function (): void {
    $actor = consoleRedeem();

    /** @var ConsoleGuard $guard */
    $guard = auth(ConsoleGuardConfiguration::GUARD);

    expect($guard->actor()?->getKey())->toBe($actor->getKey());

    // A NEW request on the SAME application — the long-lived worker
    // case. The wrapper's own memo is not the only cache: the inner
    // SessionGuard holds its own resolved user, and setRequest() does
    // not clear it.
    session()->forget(consoleGuardSessionKey());
    app()->instance('request', Request::create('/next'));

    expect($guard->actor())->toBeNull()
        ->and($guard->check())->toBeFalse();
});

it('does not carry a resolved acting principal into the next request', function (): void {
    $actor = consoleRedeem();

    $resolver = app(ActingPrincipalResolver::class);
    $first = $resolver->resolve();

    expect($first->delegatedActor?->getKey())->toBe($actor->getKey())
        ->and($resolver->resolve())->toBe($first);

    session()->forget(consoleGuardSessionKey());
    Auth::forgetGuards();
    app()->instance('request', Request::create('/next'));

    $second = $resolver->resolve();

    expect($second)->not->toBe($first)
        ->and($second->delegatedActor)->toBeNull()
        ->and($second->identifier())->toBeNull();
});

// ─── AC16: claims are SESSION-bound, not row-bound ──────────────────────────

it('does not let a later handoff change the role of an already-live session', function (): void {
    // S1 enters as a member.
    $actor = consoleActor(role: ConsoleRole::Member, displayName: 'Jane Operator');

    $this->withSession(consoleSessionState($actor));

    $this->getJson('/console-route')
        ->assertOk()
        ->assertJsonPath('role', 'member');

    // S2 — a second handoff for the SAME subject — arrives as an admin
    // acting for an agency. It rewrites the shared row.
    $promoted = consoleActor(role: ConsoleRole::Admin, displayName: 'Jane Elevated', onBehalfOf: 'Acme Agency');

    expect($promoted->getKey())->toBe($actor->getKey())
        ->and($promoted->last_handoff_role)->toBe(ConsoleRole::Admin);

    // S1's next request must still be a member, attributed to the
    // handoff S1 actually presented — not to one it never saw.
    $this->getJson('/console-route')
        ->assertOk()
        ->assertJsonPath('role', 'member')
        ->assertJsonPath('attribution', 'Jane Operator')
        ->assertJsonPath('on_behalf_of', null);
});

it('holds two concurrent sessions for one subject at the roles they each entered with', function (): void {
    // AC16 in the SHAPE OF THE BUG it guards, rather than one session
    // re-read after a row write. The escalation is: one human, two live
    // delegated sessions — a member session already open in one browser,
    // an admin session opened in another — and the shadow actor row is
    // shared by both. Reading the role off that row would silently
    // promote the member session on its very next request.
    //
    // Both sessions are live for the whole test and are interleaved, so
    // "S1 is still a member" is asserted while S2 is genuinely open, not
    // merely after S2's handoff was recorded.
    $memberSession = consoleSessionState(consoleActor(role: ConsoleRole::Member, displayName: 'Jane Member'));

    // S2: the SAME issuer + subject, so the same actor row — that is
    // what makes the two sessions share a referent and what makes
    // reading claims off it an escalation.
    $adminSession = consoleSessionState(consoleActor(role: ConsoleRole::Admin, displayName: 'Jane Admin', onBehalfOf: 'Acme Agency'));

    expect(DelegatedActor::query()->count())->toBe(1);

    // Interleaved, both live: member, admin, member, admin.
    $this->withSession($memberSession);
    $this->getJson('/console-route')
        ->assertOk()
        ->assertJsonPath('role', 'member')
        ->assertJsonPath('attribution', 'Jane Member');

    $this->withSession($adminSession);
    $this->getJson('/console-route')
        ->assertOk()
        ->assertJsonPath('role', 'admin')
        ->assertJsonPath('attribution', 'Jane Admin (Acme Agency)');

    // The one that matters: S1 is unchanged, after S2 has acted.
    $this->withSession($memberSession);
    $this->getJson('/console-route')
        ->assertOk()
        ->assertJsonPath('role', 'member')
        ->assertJsonPath('attribution', 'Jane Member')
        ->assertJsonPath('on_behalf_of', null);

    $this->withSession($adminSession);
    $this->getJson('/console-route')
        ->assertOk()
        ->assertJsonPath('role', 'admin');

    // ...and the shared row says admin the whole time, which is the
    // value a row-reading implementation would have handed S1.
    expect(DelegatedActor::query()->sole()->last_handoff_role)->toBe(ConsoleRole::Admin);
});

it('does not let a concurrent admin session promote a member session past the admin gate', function (): void {
    // The same two live sessions, through the gate that would actually
    // grant something.
    Route::middleware([StartSession::class, 'bfc.console', 'auth:'.ConsoleGuardConfiguration::GUARD, 'bfc.admin'])
        ->get('/concurrent-admin', fn (): array => ['ok' => true]);

    $memberSession = consoleSessionState(consoleActor(role: ConsoleRole::Member));
    $adminSession = consoleSessionState(consoleActor(role: ConsoleRole::Admin));

    $this->withSession($adminSession);
    $this->getJson('/concurrent-admin')->assertOk();

    $this->withSession($memberSession);
    $this->getJson('/concurrent-admin')->assertStatus(403);

    // And back again, so neither session's answer is a one-way latch.
    $this->withSession($adminSession);
    $this->getJson('/concurrent-admin')->assertOk();
});

it('refuses a delegated session whose claims cannot be read', function (string $missing): void {
    $actor = consoleActor();

    $state = consoleSessionState($actor);
    unset($state[$missing]);

    $this->withSession($state);

    // Not "defaults to member" and not "renders an empty badge": a
    // session whose claims cannot be established has none, so the
    // session is refused outright and the route answers the structured
    // 401 rather than admitting a role-less operator.
    $this->getJson('/console-route')
        ->assertStatus(401)
        ->assertJsonPath('reason', 'session_invalidated');
})->with([
    'display name' => ['bfc_console.display_name'],
    'role' => ['bfc_console.role'],
]);

it('refuses a delegated session carrying a role outside the vocabulary', function (): void {
    $actor = consoleActor();

    $this->withSession([...consoleSessionState($actor), 'bfc_console.role' => 'superadmin']);

    $this->getJson('/console-route')
        ->assertStatus(401)
        ->assertJsonPath('reason', 'session_invalidated');
});

it('carries the session claims, not the row copy, into the resolution', function (): void {
    // The row says admin/Acme; the session says member/no agency. The
    // session wins, because that is the handoff this request presented.
    $actor = consoleActor(role: ConsoleRole::Admin, displayName: 'Row Copy', onBehalfOf: 'Acme Agency');

    $this->withSession(consoleSessionState(
        $actor,
        claims: new DelegatedClaims('Session Copy', ConsoleRole::Member, null),
    ));

    $this->getJson('/console-route')
        ->assertOk()
        ->assertJsonPath('role', 'member')
        ->assertJsonPath('attribution', 'Session Copy')
        ->assertJsonPath('on_behalf_of', null);
});

// ─── A refusal is terminal on every route, not only console ones ────────────

it('resolves no local principal after a console refusal, even on an app route', function (): void {
    $user = actingUser();
    $actor = consoleActor();

    $this->actingAs($user)->withSession(consoleSessionState($actor, CarbonImmutable::now()->subMinutes(121)->getTimestamp()));

    $this->getJson('/app-route')
        ->assertOk()
        ->assertJsonPath('principal', null)
        ->assertJsonPath('refused', true)
        ->assertJsonPath('delegated_session_present', true);
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

it('never carries a co-resident actor claims on a non-delegated resolution', function (): void {
    $actor = consoleActor(role: ConsoleRole::Admin, onBehalfOf: 'Acme Agency');

    // The actor being PRESENT on a local resolution is exactly what the
    // broad local-only refusal answers on — and what the admin gate's
    // exactness depends on NOT leaking into claims: `delegated` false
    // must imply no role, or a gate branching on the role instead of on
    // the resolution would admit a delegated principal a route never
    // scoped itself to (FLEET-C-02).
    $local = ActingPrincipal::local('web', actingUser(), $actor);

    expect($local->delegated)->toBeFalse()
        ->and($local->delegatedSessionPresent())->toBeTrue()
        ->and($local->role)->toBeNull()
        ->and($local->attribution)->toBeNull()
        ->and($local->displayName)->toBeNull()
        ->and($local->onBehalfOf)->toBeNull();

    expect(ActingPrincipal::none($actor)->role)->toBeNull()
        ->and(ActingPrincipal::refused(ConsoleReentryReason::SessionInvalidated)->role)->toBeNull();
});

// ─── AC31: logout must not poison the cached guard for the next request ─────

it('does not let a logout on one request reject a different delegated session on the next', function (): void {
    $first = consoleActor(subject: 'operator_a', displayName: 'Operator A');

    /** @var ConsoleGuard $guard */
    $guard = auth(ConsoleGuardConfiguration::GUARD);

    session()->put(consoleSessionState($first));

    expect($guard->actor()?->getKey())->toBe($first->getKey());

    // Request A ends with a delegated leave (PR5's flow will call this).
    $guard->logout();

    expect($guard->actor())->toBeNull();

    // Request B, same process, SAME cached guard instance — the auth
    // manager keeps them for the life of the application — carrying a
    // different, perfectly valid delegated session.
    $second = consoleActor(subject: 'operator_b', displayName: 'Operator B');

    app()->instance('request', Request::create('/next'));

    session()->flush();

    foreach (consoleSessionState($second) as $key => $value) {
        session()->put($key, $value);
    }

    // If logout left the inner SessionGuard's sticky `loggedOut` flag
    // set, `SessionGuard::user()` returns immediately and B is wrongly
    // rejected — a cross-request state leak in a guard, the same class
    // of bug as the cached principal AC24 covers.
    expect($guard->actor()?->getKey())->toBe($second->getKey())
        ->and($guard->check())->toBeTrue()
        ->and($guard->claims()?->displayName)->toBe('Operator B');
});
