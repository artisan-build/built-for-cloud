<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Commands\SystemAuthorityCommand;
use ArtisanBuild\BuiltForCloud\Contracts\SystemAuthorityQueueEntry;
use ArtisanBuild\BuiltForCloud\Exceptions\SystemAuthorityViolation;
use ArtisanBuild\BuiltForCloud\SystemAuthorityContext;
use ArtisanBuild\BuiltForCloud\SystemAuthoritySchedule;
use ArtisanBuild\BuiltForCloud\Testing\SystemAuthorityInventory;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\HostRuntimeAuthQueuedJob;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RuntimeAuthorityQueuedJob;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RuntimeAuthorityServiceProvider;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RuntimeHumanAuthenticator;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\SafeRuntimeAuthorityQueuedJob;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Auth\SessionGuard;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Queue\Events\JobExceptionOccurred;
use Illuminate\Queue\Events\JobFailed;
use Illuminate\Queue\Events\JobProcessing;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Queue;

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
    ]))->toBe(0)
        ->and($exceptions)->toBe([[SystemAuthorityViolation::class, true, false]])
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
