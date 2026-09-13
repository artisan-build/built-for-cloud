<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\BuiltForCloudServiceProvider;
use ArtisanBuild\BuiltForCloud\Commands\SystemAuthorityCommand;
use ArtisanBuild\BuiltForCloud\Contracts\SystemAuthorityQueueEntry;
use ArtisanBuild\BuiltForCloud\Exceptions\SystemAuthorityViolation;
use ArtisanBuild\BuiltForCloud\Listeners\RefuseSystemAuthorityAuthentication;
use ArtisanBuild\BuiltForCloud\SystemAuthorityBusFrame;
use ArtisanBuild\BuiltForCloud\SystemAuthorityContext;
use ArtisanBuild\BuiltForCloud\SystemAuthoritySchedule;
use ArtisanBuild\BuiltForCloud\Testing\SystemAuthorityInventory;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\HostCopycatQueuedJob;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\HostMissingModelListener;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\HostRuntimeAuthQueuedJob;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RogueEventDispatchingGuard;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RogueFailedHandlerJob;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RogueFailThenLoginJob;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RogueLabelledMarkerJob;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RogueListenerEvent;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RogueMarkedFailingListener;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RogueMarkedMiddlewareListener;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RogueMarkedQueuedListener;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RogueMiddlewareLoginJob;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RuntimeAuthorityQueuedJob;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RuntimeAuthorityServiceProvider;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RuntimeHumanAuthenticator;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\SafeRuntimeAuthorityQueuedJob;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\SessionGuard;
use Illuminate\Bus\Dispatcher as IlluminateBusDispatcher;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Bus\Dispatcher as BusDispatcher;
use Illuminate\Events\CallQueuedListener;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Queue\CallQueuedClosure;
use Illuminate\Queue\Events\JobExceptionOccurred;
use Illuminate\Queue\Events\JobFailed;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Queue;
use ReflectionProperty;

uses(RefreshDatabase::class);

/** @return array<string, array{string}> */
function runtimeAuthenticationShapes(): array
{
    return [
        'Auth::login' => ['facade-login'],
        'auth helper login' => ['helper-login'],
        'Auth guard login' => ['facade-guard-login'],
        'injected AuthFactory guard login' => ['injected-factory-login'],
        'container auth manager login' => ['container-manager-login'],
        'container make auth login' => ['container-make-login'],
        'nullsafe guard login' => ['nullsafe-guard-login'],
        'Auth::attemptWhen' => ['attempt-when'],
        'facade root guard login' => ['facade-root-login'],
        'dynamic method login' => ['dynamic-login'],
        'helper-class indirection' => ['helper-indirection'],
    ];
}

function runtimeAuthorityUser(string $suffix = ''): User
{
    return User::query()->create([
        'name' => 'Runtime authority user',
        'email' => 'runtime-authority'.$suffix.'@example.test',
        'password' => Hash::make('runtime-authority-password'),
        'role' => UserRole::Member,
        'status' => 'active',
        'email_verified_at' => now(),
    ]);
}

beforeEach(function (): void {
    app()->register(RuntimeAuthorityServiceProvider::class);
});

it('wraps every derived package command and queued entry in the runtime authority mechanism', function (): void {
    $inventory = SystemAuthorityInventory::discover(
        [dirname(__DIR__).'/src/BuiltForCloudServiceProvider.php'],
        [dirname(__DIR__).'/src'],
    );

    foreach ($inventory['commands'] as $command) {
        expect(is_a($command, SystemAuthorityCommand::class, true))->toBeTrue();
    }

    foreach ($inventory['queued'] as $queued) {
        expect(is_a($queued, SystemAuthorityQueueEntry::class, true))->toBeTrue();
    }
});

it('refuses every known authentication shape through Artisan and leaves the guard guest', function (string $shape): void {
    $user = runtimeAuthorityUser('-command-'.$shape);

    expect(fn (): int => Artisan::call('fixture:runtime-authority', [
        'shape' => $shape,
        'user' => (string) $user->getKey(),
    ]))->toThrow(SystemAuthorityViolation::class)
        ->and(auth()->guard('web')->guest())->toBeTrue()
        ->and(app(SystemAuthorityContext::class)->active())->toBeFalse();
})->with(runtimeAuthenticationShapes());

it('does not refuse a host command that authenticates a human', function (): void {
    $user = runtimeAuthorityUser('-host-command');

    expect(Artisan::call('fixture:host-runtime-auth', [
        'user' => (string) $user->getKey(),
    ]))->toBe(0)
        ->and(auth()->guard('web')->id())->toBe($user->getAuthIdentifier())
        ->and(app(SystemAuthorityContext::class)->active())->toBeFalse();
});

it('refuses every known authentication shape through a real queue worker and does not leak into the following host job', function (): void {
    config(['queue.default' => 'database']);
    $user = runtimeAuthorityUser('-queue');
    $failed = [];
    $processing = [];

    Event::listen(JobProcessing::class, function (JobProcessing $event) use (&$processing): void {
        $processing[] = [$event->job->resolveName(), app(SystemAuthorityContext::class)->active()];
    });

    Event::listen(JobFailed::class, function (JobFailed $event) use (&$failed): void {
        $failed[] = [$event->exception::class, auth()->guard('web')->guest()];
    });

    foreach (runtimeAuthenticationShapes() as [$shape]) {
        Queue::connection('database')->push(new RuntimeAuthorityQueuedJob($shape, (string) $user->getKey()));
    }
    Queue::connection('database')->push(new SafeRuntimeAuthorityQueuedJob);
    Queue::connection('database')->push(new HostRuntimeAuthQueuedJob((string) $user->getKey()));

    expect(Artisan::call('queue:work', [
        'connection' => 'database',
        '--stop-when-empty' => true,
        '--tries' => 1,
        '--sleep' => 0,
        // queue:work defaults to --memory=128 and returns EXIT_MEMORY_LIMIT (12)
        // when the HOST process is already past that, which a full-suite run always
        // is. Without this the worker self-terminates before the leak assertions
        // below ever execute: green in isolation, vacuous in the suite.
        '--memory' => 4096,
    ]))->toBe(0)
        ->and($processing)->toHaveCount(count(runtimeAuthenticationShapes()) + 2)
        ->and(array_column($processing, 1))->toBe([
            ...array_fill(0, count(runtimeAuthenticationShapes()) + 1, true),
            false,
        ])
        ->and($failed)->toHaveCount(count(runtimeAuthenticationShapes()))
        ->and(array_unique(array_column($failed, 0)))->toBe([SystemAuthorityViolation::class])
        ->and(array_unique(array_column($failed, 1)))->toBe([true])
        ->and(config('runtime-authority.safe-package-job-finished'))->toBeTrue()
        ->and(config('runtime-authority.host-job-user'))->toBe($user->getAuthIdentifier())
        ->and(app(SystemAuthorityContext::class)->active())->toBeFalse();
});

it('clears queue authority on an exception that will be retried', function (): void {
    config(['queue.default' => 'database']);
    $user = runtimeAuthorityUser('-queue-retry');
    $exceptions = [];

    Event::listen(JobExceptionOccurred::class, function (JobExceptionOccurred $event) use (&$exceptions): void {
        $exceptions[] = [
            $event->exception::class,
            auth()->guard('web')->guest(),
            app(SystemAuthorityContext::class)->active(),
        ];
    });
    Queue::connection('database')->push(new RuntimeAuthorityQueuedJob(
        'facade-login',
        (string) $user->getKey(),
    ));

    expect(Artisan::call('queue:work', [
        'connection' => 'database',
        '--once' => true,
        '--tries' => 2,
        '--memory' => 4096,
    ]))->toBe(0)
        // The frame is deliberately STILL ACTIVE at JobExceptionOccurred: that event
        // fires while package code can still run — the stack unwinds back through the
        // job's own middleware afterwards, and a fail() inside handle() dispatches its
        // event and returns to the handler. Releasing there was delta-4's A2 defect.
        // Release happens on JobAttempted, which Worker::process and
        // SyncQueue::executeJob both dispatch from a `finally`.
        ->and($exceptions)->toBe([[SystemAuthorityViolation::class, true, true]])
        // And it IS released by the time the worker returns, so nothing leaks into the
        // next job.
        ->and(app(SystemAuthorityContext::class)->active())->toBeFalse();
});

it('refuses every known authentication shape through a package schedule callback and leaves the guard guest', function (string $shape): void {
    $user = runtimeAuthorityUser('-schedule-'.$shape);
    $event = app(SystemAuthoritySchedule::class)->call(
        app(Schedule::class),
        fn (): mixed => app(RuntimeHumanAuthenticator::class)->run(
            $shape,
            (string) $user->getKey(),
            app(AuthFactory::class),
        ),
    );

    expect(fn (): mixed => $event->run(app()))->toThrow(SystemAuthorityViolation::class)
        ->and(auth()->guard('web')->guest())->toBeTrue()
        ->and(app(SystemAuthorityContext::class)->active())->toBeFalse();
})->with(runtimeAuthenticationShapes());

it('refuses bound-user actor synthesis through commands, queues, and schedules', function (): void {
    $user = runtimeAuthorityUser('-bound-user');

    expect(fn (): int => Artisan::call('fixture:runtime-authority', [
        'shape' => 'bound-user-actor',
        'user' => (string) $user->getKey(),
    ]))->toThrow(SystemAuthorityViolation::class, 'cannot synthesize a bound-user audit actor');

    config(['queue.default' => 'database']);
    $violations = [];
    Event::listen(JobFailed::class, function (JobFailed $event) use (&$violations): void {
        if ($event->exception instanceof SystemAuthorityViolation) {
            $violations[] = $event->exception->getMessage();
        }
    });
    Queue::connection('database')->push(new RuntimeAuthorityQueuedJob('bound-user-actor', (string) $user->getKey()));
    Artisan::call('queue:work', [
        'connection' => 'database',
        '--once' => true,
        '--tries' => 1,
        '--memory' => 4096,
    ]);
    expect($violations)->toBe(['A Built for Cloud system-authority entry cannot synthesize a bound-user audit actor.']);

    $event = app(SystemAuthoritySchedule::class)->call(
        app(Schedule::class),
        fn (): mixed => app(RuntimeHumanAuthenticator::class)->run(
            'bound-user-actor',
            (string) $user->getKey(),
            app(AuthFactory::class),
        ),
    );
    expect(fn (): mixed => $event->run(app()))->toThrow(
        SystemAuthorityViolation::class,
        'cannot synthesize a bound-user audit actor',
    )->and(app(SystemAuthorityContext::class)->active())->toBeFalse();
});

it('refuses remember-me restoration through the Login event and leaves the guard guest', function (): void {
    $user = runtimeAuthorityUser('-recaller');
    $user->setRememberToken('runtime-recaller-token');
    $user->save();

    $guard = auth()->guard('web');
    expect($guard)->toBeInstanceOf(SessionGuard::class);
    assert($guard instanceof SessionGuard);
    $recaller = implode('|', [
        $user->getAuthIdentifier(),
        $user->getRememberToken(),
        $guard->hashPasswordForCookie($user->getAuthPassword()),
    ]);
    $guard->setRequest(request()->duplicate(cookies: [$guard->getRecallerName() => $recaller]));

    expect(fn (): mixed => app(SystemAuthorityContext::class)->run(fn (): mixed => $guard->user()))
        ->toThrow(SystemAuthorityViolation::class)
        ->and($guard->guest())->toBeTrue()
        ->and(app(SystemAuthorityContext::class)->active())->toBeFalse();
});

it('pins every published system-authority boundary statement to the code it describes', function (): void {
    // A disclosure nothing pins is the defect class this slice kept reproducing: a
    // document that claims coverage the code does not have, with nothing going red.
    // So each fact below is DERIVED from the implementation and then required to
    // appear in both published surfaces.
    $root = dirname(__DIR__);
    // Whitespace is normalised because these are wrapped markdown documents: a
    // phrase that straddles a line break is present to a reader and invisible to a
    // naive substring match. That exact false negative bit this slice twice.
    $flatten = static fn (string $path): string => (string) preg_replace(
        '/\s+/', ' ', (string) file_get_contents($path),
    );
    $readme = $flatten($root.'/README.md');
    $limits = $flatten($root.'/docs/system-authority-instrument-limits.md');

    // 1. The listened events, derived from the listener's own signature and
    //    confirmed against the booted dispatcher. Adding a third event to the union,
    //    or registering one the documents do not name, reds this.
    $parameter = (new ReflectionMethod(RefuseSystemAuthorityAuthentication::class, 'handle'))->getParameters()[0];
    $type = $parameter->getType();
    $events = array_map(
        static fn (ReflectionNamedType $named): string => $named->getName(),
        $type instanceof ReflectionUnionType ? $type->getTypes() : [$type],
    );

    expect($events)->toEqualCanonicalizing([Authenticated::class, Login::class]);

    // hasListeners() is NOT enough: another listener on the same event satisfies it
    // and the refusal registration can be deleted with this test still green. That
    // false positive was real - Login already carries EvictConsolePrincipal - so
    // assert THIS listener is registered for each event.
    $raw = Event::getRawListeners();

    foreach ($events as $event) {
        $registered = [];

        foreach (($raw[$event] ?? []) as $listener) {
            if (is_array($listener) && isset($listener[0])) {
                $registered[] = is_string($listener[0]) ? $listener[0] : $listener[0]::class;
            } elseif (is_string($listener)) {
                $registered[] = strstr($listener, '@', true) ?: $listener;
            }
        }

        expect($registered)->toContain(RefuseSystemAuthorityAuthentication::class)
            ->and($readme)->toContain(class_basename($event))
            ->and($limits)->toContain(class_basename($event));
    }

    // 2. The entry kinds, derived from every file that OPENS the context. A fourth
    //    entry kind cannot be added without this failing, which forces the
    //    documents to describe it.
    $openers = [];
    foreach ((new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root.'/src'))) as $file) {
        if (! $file->isFile() || $file->getExtension() !== 'php') {
            continue;
        }
        $source = (string) file_get_contents($file->getPathname());
        if (str_contains($source, 'SystemAuthorityContext')
            && preg_match('/->(?:run|enter)\s*\(/', $source) === 1
            && $file->getFilename() !== 'SystemAuthorityContext.php') {
            $openers[] = $file->getBasename('.php');
        }
    }

    expect($openers)->toEqualCanonicalizing([
        'SystemAuthorityCommand',    // package commands, framed at invocation
        'SystemAuthorityBusFrame',   // package queue entries, framed at invocation
        'SystemAuthorityQueueScope', // the same entries, framed again from queue events
        'SystemAuthoritySchedule',   // package-registered schedule callbacks
    ]);

    foreach (['command', 'schedule'] as $kind) {
        expect(strtolower($readme))->toContain($kind)
            ->and(strtolower($limits))->toContain($kind);
    }
    expect(str_contains($readme, 'ShouldQueue') || str_contains($readme, 'queued jobs'))->toBeTrue();

    // 3. THE CLAIMS, asserted as whole sentences rather than as keywords.
    //    A keyword pin is defeatable: rewriting the README sentence to invert its
    //    meaning while keeping every keyword passed the earlier version of this test.
    //    Each sentence below carries a claim, so inverting or narrowing one changes
    //    the sentence and reds this. Both published surfaces must state each claim
    //    IDENTICALLY, which is the other thing that had drifted: the two documents
    //    previously scoped the bound differently.
    $claims = [
        'The bound covers any guard that dispatches `Authenticated` or `Login`, not only `SessionGuard`.',
        // The CLASS sentence. Four attempts each disclosed shapes and missed the next
        // one, so the published bound is stated over the class and this pins that
        // wording, not a list.
        '**Any package code that runs outside a framed invocation is outside the bound.**',
        'any callback registered for later invocation, such as `defer()`, `app()->terminating()`, a listener registered at runtime, a shutdown function, or a chain or batch `catch`/`finally` callback; and any callback attached to a schedule event, including its `before`/`after` hooks and its `when`/`skip` filters.',
        'A queued closure dispatched by package code is never framed. Its declaring file does not survive serialisation, and the scope class that does survive is caller-settable, so its origin cannot be established as identity.',
        "In-process tampering switches the bound off: removing the listeners, replacing a guard's event dispatcher, or rebinding the system-authority context. A host that calls `Bus::pipeThrough()` after this package boots also replaces the pipe array and reverts the bound to framing by queue events alone.",
        "A queued entry's own `middleware()` and its `failed()` handler are inside the frame.",
        // Pinned because the stale version of this sentence — naming processed, failed
        // and exception as the release events — stayed live and green after the release
        // moved to JobAttempted.
        'It is deliberately NOT released on `JobProcessed`, `JobFailed` or `JobExceptionOccurred`: each of those fires while package code can still run.',
        // Pinned because this sentence carried a FALSE clause at the previous HEAD - it
        // claimed identity could come from a queued closure's declaring file, after the
        // closure branch had been withdrawn.
        'Never from a display name, which a job can choose.',
        'Each limit above carries an open `risk=security` debt row, so any future package change that reaches one is reviewed against it.',
    ];

    foreach ($claims as $claim) {
        expect($readme)->toContain($claim)
            ->and($limits)->toContain($claim);
    }

    // 4. LIMIT OF THIS PIN, stated rather than implied: it asserts that each claim is
    //    PRESENT and that both documents agree. It cannot detect a CONTRADICTING
    //    sentence added elsewhere in either file — a judge drift proved that by adding
    //    "Package queued closures are framed by the same pipe." and staying green.
    //    Presence matching cannot carry that; the executed controls below are what
    //    keep the behavioural claims honest.
    //
    //    The broadest claim above is not left as prose: narrowing the listener to
    //    SessionGuard reds the executed control in this file, so the sentence and the
    //    behaviour cannot disagree.
    expect((string) file_get_contents(__FILE__))
        ->toContain('RogueEventDispatchingGuard');

    // 5. The listener must refuse on the EVENT, with no guard-type gate deciding it.
    $listener = (string) file_get_contents($root.'/src/Listeners/RefuseSystemAuthorityAuthentication.php');
    $beforeThrow = strstr($listener, 'throw SystemAuthorityViolation', true) ?: '';

    expect($beforeThrow)->not->toContain('instanceof RequestGuard')
        ->and($beforeThrow)->toContain('context->active()');

    // 6. The advisory demotion: the scanner must not be described as enforcement.
    expect($limits)->toContain('advisory')
        ->and($limits)->toContain('does not carry the runtime authentication');
});

it('frames a package queue entry at its invocation, whatever route dispatched it', function (
    string $fixture, string $shape
): void {
    // Each of these three reached a real login before the frame moved from queue
    // EVENTS to the dispatched invocation. They are the executed controls for that
    // move, and each names the mechanism that used to let it through.
    config(['auth.guards.web' => ['driver' => 'session', 'provider' => 'users'], 'queue.default' => 'sync']);
    $user = runtimeAuthorityUser('-frame-'.$shape);

    expect(auth()->guard('web')->guest())->toBeTrue();

    $job = $fixture === RuntimeAuthorityQueuedJob::class
        ? new RuntimeAuthorityQueuedJob('facade-login', (string) $user->getKey())
        : new $fixture((string) $user->getKey());

    expect(fn () => app(BusDispatcher::class)->dispatchSync($job))
        ->toThrow(SystemAuthorityViolation::class)
        ->and(auth()->guard('web')->guest())->toBeTrue();
})->with([
    // identity used to come from $job->resolveName(), a caller-settable displayName
    'display name differing from the class' => [RogueLabelledMarkerJob::class, 'label'],
    // fail() dispatches JobFailed synchronously, then the handler's finally runs
    'fail() then authenticating in finally' => [RogueFailThenLoginJob::class, 'fail'],
    // dispatchSync/dispatchNow fire no queue events at all
    'synchronous dispatch of a marked job' => [RuntimeAuthorityQueuedJob::class, 'sync'],
]);

it('leaves host queue entries unframed, by object identity rather than by name', function (): void {
    config(['auth.guards.web' => ['driver' => 'session', 'provider' => 'users'], 'queue.default' => 'sync']);
    $user = runtimeAuthorityUser('-frame-host');

    // A host job carrying no package marker authenticates freely.
    app(BusDispatcher::class)->dispatchSync(new HostRuntimeAuthQueuedJob((string) $user->getKey()));
    expect(auth()->guard('web')->id())->toBe($user->getAuthIdentifier());

    // A closure declared OUTSIDE the package is host work too, even though a queued
    // closure carries no class to mark.
    auth()->guard('web')->logout();
    $id = (string) $user->getKey();
    app(BusDispatcher::class)->dispatchSync(CallQueuedClosure::create(function () use ($id): void {
        Auth::guard('web')->loginUsingId($id);
    }));

    expect(auth()->guard('web')->id())->toBe($user->getAuthIdentifier());
});

it('refuses a non-SessionGuard guard that dispatches the events, which is what the published bound says', function (): void {
    // The limits document states the bound over "a guard that dispatches Authenticated
    // or Login", not over SessionGuard. Every other control uses SessionGuard, so that
    // wording rested on an inference. This executes it: narrowing the listener to
    // SessionGuard reds this test.
    $user = runtimeAuthorityUser('-rogue-guard');
    $guard = new RogueEventDispatchingGuard(app('events'));

    expect(fn () => app(SystemAuthorityContext::class)->run(static fn (): mixed => $guard->setUser($user)))
        ->toThrow(SystemAuthorityViolation::class);

    // Outside the frame the same guard is untouched.
    $guard->setUser($user);
    expect($guard->check())->toBeTrue();
});

it('frames package code that runs outside handle(): the job\'s own middleware, on both routes', function (
    string $when, bool $spoof, string $route
): void {
    // CallQueuedHandler pipes a job through its own middleware() and only calls
    // dispatchNow() in that pipeline's `then`, so middleware runs one layer outside
    // the invocation the bus pipe wraps. `before` was reachable by spoofing the
    // display name the queue frame used for identity; `after` needed no label at all,
    // because handle() had returned and released the invocation frame. Both are now
    // covered by identifying on the payload's commandName and releasing on
    // JobAttempted.
    config(['auth.guards.web' => ['driver' => 'session', 'provider' => 'users']]);
    $user = runtimeAuthorityUser('-mw-'.$when.($spoof ? '-spoof' : '').'-'.$route);
    $job = new RogueMiddlewareLoginJob((string) $user->getKey(), $when, $spoof);

    if ($route === 'sync') {
        try {
            Queue::connection('sync')->push($job);
        } catch (SystemAuthorityViolation) {
            // The sync driver rethrows to the caller; the worker records it instead.
        }
    } else {
        config(['queue.default' => 'database']);
        Queue::connection('database')->push($job);
        Artisan::call('queue:work', ['connection' => 'database', '--once' => true, '--tries' => 1, '--memory' => 4096]);
    }

    // The liveness marker is asserted FIRST: without it, "not authenticated" would
    // also be true of a job that never ran.
    expect(Cache::get('bfc-test.middleware-ran.'.$user->getKey()))->toBeTrue()
        ->and(auth()->guard('web')->guest())->toBeTrue()
        ->and(app(SystemAuthorityContext::class)->active())->toBeFalse();
})->with([
    'before next, display name spoofed, sync queue' => ['before', true, 'sync'],
    'before next, display name spoofed, real worker' => ['before', true, 'worker'],
    'after next, no display name, sync queue' => ['after', false, 'sync'],
    'after next, no display name, real worker' => ['after', false, 'worker'],
]);

it('takes queue identity from the class, so a host job wearing a package display name stays unframed', function (): void {
    // The mirror of the control above: identity must come from the payload's
    // commandName, so copying a package job's display name onto host work must not
    // pull that work into the package's bound.
    config(['auth.guards.web' => ['driver' => 'session', 'provider' => 'users']]);
    $user = runtimeAuthorityUser('-copycat');

    // The label is COPIED from a package job, which is what makes this discriminating:
    // with identity taken from resolveName() the copied name wins and the host job is
    // framed, so this reds. The earlier version of this control declared no display
    // name at all and stayed green either way — a control that reported coverage it
    // did not have.
    Queue::connection('sync')->push(new HostCopycatQueuedJob((string) $user->getKey()));

    expect(auth()->guard('web')->id())->toBe($user->getAuthIdentifier());
});

it('frames a package queued listener through the wrapper the framework executes it in', function (): void {
    // Deleting the CallQueuedListener unwrap in the pipe must red this: the marker is
    // on the listener, never on the wrapper.
    config(['auth.guards.web' => ['driver' => 'session', 'provider' => 'users']]);
    $user = runtimeAuthorityUser('-queued-listener');
    $event = new stdClass;
    $event->userId = (string) $user->getKey();

    expect(fn () => app(BusDispatcher::class)->dispatchSync(
        new CallQueuedListener(RogueMarkedQueuedListener::class, 'handle', [$event]),
    ))->toThrow(SystemAuthorityViolation::class)
        ->and(auth()->guard('web')->guest())->toBeTrue();
});

it('appends its bus pipe, preserving one an earlier provider registered', function (): void {
    // The limits document says the pipe is APPENDED rather than replacing the
    // dispatcher's pipes. Nothing executed that before, so replacing append with a
    // bare pipeThrough() passed every test.
    $dispatcher = app(BusDispatcher::class);
    $pipes = (new ReflectionProperty(IlluminateBusDispatcher::class, 'pipes'))->getValue($dispatcher);

    expect($pipes)->toContain(SystemAuthorityBusFrame::class);

    // Set a sentinel WITHOUT the package pipe, so the registration path actually runs
    // rather than short-circuiting on its idempotence guard. Registering blind with
    // pipeThrough([self]) drops the sentinel and reds this.
    $dispatcher->pipeThrough(['coord.sentinel.pipe']);
    (function (): void {
        $this->frameQueueEntriesByInvocation();
    })->call(app()->getProvider(BuiltForCloudServiceProvider::class));

    $after = (new ReflectionProperty(IlluminateBusDispatcher::class, 'pipes'))->getValue($dispatcher);

    expect($after)->toContain('coord.sentinel.pipe')
        ->and($after)->toContain(SystemAuthorityBusFrame::class);
});

it('frames a queued entry\'s failed() handler on both routes', function (string $route): void {
    // Releasing on JobAttempted rather than on JobFailed brought failed() inside the
    // frame, which RETIRED a disclosure rather than adding one. It is a claimed
    // property now, so it carries a control — with a liveness marker, because "not
    // authenticated" is also true of a handler that never ran.
    config(['auth.guards.web' => ['driver' => 'session', 'provider' => 'users']]);
    $user = runtimeAuthorityUser('-failed-'.$route);
    $job = new RogueFailedHandlerJob((string) $user->getKey());

    if ($route === 'sync') {
        try {
            Queue::connection('sync')->push($job);
        } catch (Throwable) {
            // sync rethrows to the caller
        }
    } else {
        config(['queue.default' => 'database']);
        Queue::connection('database')->push($job);
        Artisan::call('queue:work', ['connection' => 'database', '--once' => true, '--tries' => 1, '--memory' => 4096]);
    }

    expect(Cache::get('bfc-test.failed-ran.'.$user->getKey()))->toBeTrue()
        ->and(auth()->guard('web')->guest())->toBeTrue();
})->with(['sync', 'worker']);

it('frames a package queued LISTENER through the real event queueing path, on both routes', function (
    string $listener, string $marker, string $connection
): void {
    // commandName for every queued listener is the CallQueuedListener WRAPPER, so
    // reading it alone left the listener's failed() handler and its returned
    // middleware outside both frames. Driven through Event::listen/Event::dispatch,
    // which is how the framework actually queues a listener, rather than by building
    // the wrapper by hand — the earlier control did that and could only see handle().
    config([
        'auth.guards.web' => ['driver' => 'session', 'provider' => 'users'],
        'queue.default' => $connection,
    ]);
    $user = runtimeAuthorityUser('-ql-'.$marker.'-'.$connection);
    Event::listen(RogueListenerEvent::class, $listener);

    try {
        Event::dispatch(new RogueListenerEvent((string) $user->getKey(), $connection));
    } catch (Throwable) {
        // sync surfaces the refusal to the caller; the worker records it instead.
    }

    if ($connection === 'database') {
        Artisan::call('queue:work', ['connection' => 'database', '--once' => true, '--tries' => 1, '--memory' => 4096]);
    }

    // Liveness first: "not authenticated" is also true of code that never ran.
    expect(Cache::get('bfc-test.'.$marker.'.'.$user->getKey()))->toBeTrue()
        ->and(auth()->guard('web')->guest())->toBeTrue();
})->with([
    'failed() handler, sync' => [RogueMarkedFailingListener::class, 'listener-failed-ran', 'sync'],
    'failed() handler, real worker' => [RogueMarkedFailingListener::class, 'listener-failed-ran', 'database'],
    'returned middleware, sync' => [RogueMarkedMiddlewareListener::class, 'listener-mw-ran', 'sync'],
    'returned middleware, real worker' => [RogueMarkedMiddlewareListener::class, 'listener-mw-ran', 'database'],
]);

it('leaves a host queued listener whose model was deleted to the framework, deleting it rather than failing it', function (): void {
    // Reading the wrapper's marked class means unserialising the command, and
    // SerializesModels restores models while doing it. A model deleted since dispatch
    // throws there, and if that escaped this listener it would turn a job the
    // framework deletes under deleteWhenMissingModels into a failure. The unwrap
    // catches everything and frames the entry when it cannot read the class, so the
    // framework's own handling is untouched.
    config(['queue.default' => 'database']);
    $user = runtimeAuthorityUser('-missing-model');
    Event::listen(RogueListenerEvent::class, HostMissingModelListener::class);

    Event::dispatch(new RogueListenerEvent((string) $user->getKey(), 'database'));
    expect(DB::table('jobs')->count())->toBe(1);

    $user->delete();
    Artisan::call('queue:work', ['connection' => 'database', '--once' => true, '--tries' => 1, '--memory' => 4096]);

    expect(DB::table('failed_jobs')->count())->toBe(0)
        ->and(DB::table('jobs')->count())->toBe(0);
});
