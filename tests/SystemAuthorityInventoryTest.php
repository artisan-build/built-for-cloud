<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Commands\ConsoleReKeyCommand;
use ArtisanBuild\BuiltForCloud\Commands\ConsoleRetireKeyCommand;
use ArtisanBuild\BuiltForCloud\Commands\CreateAdminCommand;
use ArtisanBuild\BuiltForCloud\Commands\CredentialActivateCommand;
use ArtisanBuild\BuiltForCloud\Commands\CredentialListCommand;
use ArtisanBuild\BuiltForCloud\Commands\CredentialMintCommand;
use ArtisanBuild\BuiltForCloud\Commands\CredentialRevokeCommand;
use ArtisanBuild\BuiltForCloud\Commands\CredentialRotateCommand;
use ArtisanBuild\BuiltForCloud\Commands\HmacRewrapCommand;
use ArtisanBuild\BuiltForCloud\Commands\InstallOperatorCredentialCommand;
use ArtisanBuild\BuiltForCloud\Commands\OutboxDrainCommand;
use ArtisanBuild\BuiltForCloud\Commands\OwnershipMintClaimCommand;
use ArtisanBuild\BuiltForCloud\Commands\OwnershipRemintOwnerTokenCommand;
use ArtisanBuild\BuiltForCloud\Commands\SubjectOffboardCommand;
use ArtisanBuild\BuiltForCloud\Commands\WarnExpiringCredentialsCommand;
use ArtisanBuild\BuiltForCloud\Jobs\DeliverOwnershipWebhook;
use ArtisanBuild\BuiltForCloud\Testing\SystemAuthorityInventory;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RogueAfterCommitQueuedJob;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RogueAttemptLoginCommand;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RogueAuthFacadeLoginCommand;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RogueAuthGuardLoginCommand;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RogueAuthHelperLoginCommand;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RogueCommentedHumanCommand;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RogueConditionalScheduleServiceProvider;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RogueContainerAuthCommand;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RogueHumanQueuedJob;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RogueInheritedQueuedJob;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RogueMislabelledScheduleServiceProvider;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RogueOnceUsingIdLoginCommand;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RogueRoleExistsCommand;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RogueScheduleRegistration;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RogueScheduleServiceProvider;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RogueSystemAuthorityServiceProvider;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RogueUserPrincipalCommand;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RogueUserRoleCommand;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\UnclassifiedStateChangingCommand;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\UserWritingInstallCommand;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Hash;

uses(RefreshDatabase::class);

function p5eProvider(): string
{
    return dirname(__DIR__).'/src/BuiltForCloudServiceProvider.php';
}

function p5eFixtureProvider(): string
{
    return __DIR__.'/Fixtures/RogueSystemAuthorityServiceProvider.php';
}

/** @return array<string, list<class-string>> */
function p5eCommandDisposition(): array
{
    return [
        'cloud-wrapping' => [
            OwnershipMintClaimCommand::class,
            OwnershipRemintOwnerTokenCommand::class,
            CreateAdminCommand::class,
        ],
        'local-only-mandatory-flag' => [
            CredentialMintCommand::class,
            CredentialRotateCommand::class,
            CredentialActivateCommand::class,
            CredentialRevokeCommand::class,
            SubjectOffboardCommand::class,
            ConsoleReKeyCommand::class,
            ConsoleRetireKeyCommand::class,
        ],
        'in-environment-maintenance' => [
            HmacRewrapCommand::class,
            OutboxDrainCommand::class,
            WarnExpiringCredentialsCommand::class,
        ],
        'install-scaffold' => [InstallOperatorCredentialCommand::class],
        'read-only' => [CredentialListCommand::class],
    ];
}

/** @return list<string> */
function p5eSorted(array $values): array
{
    sort($values);

    return array_values($values);
}

function p5eSource(string $class): string
{
    $file = (new ReflectionClass($class))->getFileName();

    return is_string($file) ? (string) file_get_contents($file) : '';
}

it('derives commands, queued work, and the exact empty schedule ceiling without human authority', function (): void {
    $inventory = SystemAuthorityInventory::discover([p5eProvider()], [dirname(__DIR__).'/src']);
    $expectedCommands = p5eSorted(array_merge(...array_values(p5eCommandDisposition())));

    expect($inventory['commands'])->toBe($expectedCommands)
        ->and($inventory['commands'])->toHaveCount(15)
        ->and($inventory['queued'])->toBe([DeliverOwnershipWebhook::class])
        ->and($inventory['scheduled'])->toBe([])
        ->and($inventory['violations'])->toBe([
            'commands' => [],
            'queued' => [],
            'scheduled' => [],
        ]);
});

it('reports the command inventory controls that resolve a human principal and derive authority from UserRole', function (): void {
    $inventory = SystemAuthorityInventory::discover(
        [p5eProvider(), p5eFixtureProvider()],
        [dirname(__DIR__).'/src', __DIR__.'/Fixtures'],
    );

    expect($inventory['commands'])->toContain(
        RogueCommentedHumanCommand::class,
        RogueUserPrincipalCommand::class,
        RogueUserRoleCommand::class,
        UnclassifiedStateChangingCommand::class,
    )->and($inventory['violations']['commands'])->toContain(
        'human-principal:'.RogueUserPrincipalCommand::class,
        'human-role:'.RogueUserRoleCommand::class,
        'synthesized-human:'.RogueCommentedHumanCommand::class,
    );
});

it('reports each auth-typed login spelling and proves the isolated command really authenticates', function (string $class, string $signature): void {
    $user = User::query()->create([
        'name' => 'Already fetched login user',
        'email' => str_replace(':', '-', $signature).'@example.test',
        'password' => Hash::make('inventory-password'),
        'role' => UserRole::Member,
    ]);
    app()->instance(Authenticatable::class, $user);
    app()->register(RogueSystemAuthorityServiceProvider::class);
    $file = (new ReflectionClass($class))->getFileName();
    $inventory = SystemAuthorityInventory::discover(
        [p5eFixtureProvider()],
        [is_string($file) ? $file : ''],
    );

    expect(auth()->guest())->toBeTrue()
        ->and($inventory['violations']['commands'])->toContain(
            'human-principal:'.$class,
            'synthesized-human:'.$class,
        )
        ->and(Artisan::call($signature))->toBe(0)
        ->and(auth()->check())->toBeTrue()
        ->and(auth()->id())->toBe($user->getAuthIdentifier());
})->with([
    'Auth::login' => [RogueAuthFacadeLoginCommand::class, 'fixture:auth-facade-login'],
    'auth helper login' => [RogueAuthHelperLoginCommand::class, 'fixture:auth-helper-login'],
    'Auth guard login' => [RogueAuthGuardLoginCommand::class, 'fixture:auth-guard-login'],
]);

it('does not subtract a role constraint in a User where array as though it were a write', function (): void {
    $inventory = SystemAuthorityInventory::discover(
        [p5eFixtureProvider()],
        [__DIR__.'/Fixtures/RogueRoleExistsCommand.php'],
    );

    expect($inventory['commands'])->toContain(RogueRoleExistsCommand::class)
        ->and($inventory['violations']['commands'])->toContain(
            'human-principal:'.RogueRoleExistsCommand::class,
            'human-role:'.RogueRoleExistsCommand::class,
        );
});

it('reports a queued job that resolves and synthesizes a human principal', function (): void {
    $production = SystemAuthorityInventory::discover([p5eProvider()], [dirname(__DIR__).'/src']);
    $controlled = SystemAuthorityInventory::discover(
        [p5eProvider()],
        [dirname(__DIR__).'/src', __DIR__.'/Fixtures/RogueHumanQueuedJob.php'],
    );

    expect($production['queued'])->not->toContain(RogueHumanQueuedJob::class)
        ->and($controlled['queued'])->toContain(RogueHumanQueuedJob::class)
        ->and($controlled['violations']['queued'])->toContain(
            'human-principal:'.RogueHumanQueuedJob::class,
            'synthesized-human:'.RogueHumanQueuedJob::class,
        );
});

it('derives after-commit and inherited queue implementations from the framework interface', function (): void {
    $controlled = SystemAuthorityInventory::discover(
        [p5eProvider()],
        [
            dirname(__DIR__).'/src',
            __DIR__.'/Fixtures/RogueAfterCommitQueuedJob.php',
            __DIR__.'/Fixtures/InheritedQueuedParent.php',
            __DIR__.'/Fixtures/RogueInheritedQueuedJob.php',
        ],
    );

    expect($controlled['queued'])->toContain(
        RogueAfterCommitQueuedJob::class,
        RogueInheritedQueuedJob::class,
    )->and($controlled['violations']['queued'])->toContain(
        'synthesized-human:'.RogueAfterCommitQueuedJob::class,
        'synthesized-human:'.RogueInheritedQueuedJob::class,
    );
});

it('positive-controls the runtime schedule registry through package-style callAfterResolving registration', function (): void {
    $production = SystemAuthorityInventory::discover([p5eProvider()], [dirname(__DIR__).'/src']);
    app()->register(RogueScheduleServiceProvider::class);
    $controlled = SystemAuthorityInventory::discover(
        [p5eProvider(), __DIR__.'/Fixtures/RogueScheduleServiceProvider.php'],
        [
            dirname(__DIR__).'/src',
            __DIR__.'/Fixtures/RogueScheduleServiceProvider.php',
            __DIR__.'/Fixtures/RogueScheduleRegistration.php',
        ],
    );

    expect($production['scheduled'])->toBe([])
        ->and($controlled['scheduled'])->toBe([RogueScheduleRegistration::class])
        ->and($controlled['violations']['scheduled'])->toContain(
            'human-role:'.RogueScheduleRegistration::class,
        );
});

it('keys scanned source by declared classes with zero comment-derived mis-keys', function (): void {
    $method = (new ReflectionClass(SystemAuthorityInventory::class))->getMethod('sources');
    /** @var array<string, string> $sources */
    $sources = $method->invoke(null, [dirname(__DIR__).'/src']);
    $miskeyed = array_values(array_filter(
        array_keys($sources),
        static fn (string $class): bool => ! class_exists($class),
    ));

    expect($miskeyed)->toBe([]);
});

it('lets create-admin write the initial user without authenticating as that user', function (): void {
    expect(auth()->guest())->toBeTrue();

    $exit = Artisan::call('create-admin', [
        '--execute' => true,
        '--email' => 'inventory-owner@example.test',
        '--name' => 'Inventory Owner',
        '--password-hash' => Hash::make('inventory-password'),
    ]);

    expect($exit)->toBe(0)
        ->and(User::query()->where('email', 'inventory-owner@example.test')->where('role', 'owner')->exists())->toBeTrue()
        ->and(auth()->guest())->toBeTrue();
});

it('distinguishes user writes from human authentication without a command-name carveout', function (): void {
    $inventory = SystemAuthorityInventory::discover(
        [p5eProvider(), p5eFixtureProvider()],
        [dirname(__DIR__).'/src', __DIR__.'/Fixtures'],
    );

    expect($inventory['commands'])->toContain(UserWritingInstallCommand::class)
        ->and(array_values(array_filter(
            $inventory['violations']['commands'],
            static fn (string $violation): bool => str_ends_with($violation, UserWritingInstallCommand::class),
        )))->toBe([])
        ->and(p5eSource(SystemAuthorityInventory::class))->not->toContain('CreateAdminCommand');
});

it('states the source-level advisory instrument limits truthfully', function (): void {
    expect(p5eSource(SystemAuthorityInventory::class))->toContain(
        'Queue membership uses the framework interface at runtime',
        'actual callable/command identity',
        'advisory source-level',
        'facades',
        'helper indirection',
        'dynamic registrations',
        'transitive calls',
        'consumer/vendor code',
    );
});

it('attributes a mislabelled scheduled closure from its real callable instead of its display name', function (): void {
    app()->register(RogueMislabelledScheduleServiceProvider::class);
    $provider = __DIR__.'/Fixtures/RogueMislabelledScheduleServiceProvider.php';
    $inventory = SystemAuthorityInventory::discover([p5eProvider()], [dirname(__DIR__).'/src', $provider]);

    expect($inventory['scheduled'])->toHaveCount(1)
        ->and($inventory['scheduled'][0])->toStartWith('Closure@'.$provider.':')
        ->and($inventory['violations']['scheduled'])->toContain(
            'synthesized-human:'.$inventory['scheduled'][0],
        )->not->toContain('human-role:'.CreateAdminCommand::class);
});

it('keeps an unnamed closure outside scanned roots fail closed', function (): void {
    app(Schedule::class)->call(static fn (): bool => true);
    $inventory = SystemAuthorityInventory::discover([p5eProvider()], [dirname(__DIR__).'/src']);

    expect($inventory['scheduled'])->toHaveCount(1)
        ->and($inventory['violations']['scheduled'])->toContain(
            'uninspectable-schedule:'.$inventory['scheduled'][0],
        );
});

it('attributes a command-string schedule through the registered command inventory', function (): void {
    app(Schedule::class)->command(RogueRoleExistsCommand::class);
    $inventory = SystemAuthorityInventory::discover(
        [p5eFixtureProvider()],
        [__DIR__.'/Fixtures/RogueRoleExistsCommand.php'],
    );

    expect($inventory['scheduled'])->toBe([RogueRoleExistsCommand::class])
        ->and($inventory['violations']['scheduled'])->toContain(
            'human-role:'.RogueRoleExistsCommand::class,
        );
});

it('tripwires a unit-test-gated schedule registration that the runtime registry cannot see', function (): void {
    app()->register(RogueConditionalScheduleServiceProvider::class);
    $provider = __DIR__.'/Fixtures/RogueConditionalScheduleServiceProvider.php';
    $inventory = SystemAuthorityInventory::discover([p5eProvider()], [dirname(__DIR__).'/src', $provider]);

    expect($inventory['scheduled'])->toBe([])
        ->and($inventory['violations']['scheduled'])->toContain(
            'schedule-reference:'.RogueConditionalScheduleServiceProvider::class,
        );
});

it('classifies every derived command exactly once across the five frozen dispositions', function (): void {
    $inventory = SystemAuthorityInventory::discover([p5eProvider()], [dirname(__DIR__).'/src']);
    $disposition = p5eCommandDisposition();
    $members = array_merge(...array_values($disposition));

    expect(array_keys($disposition))->toBe([
        'cloud-wrapping',
        'local-only-mandatory-flag',
        'in-environment-maintenance',
        'install-scaffold',
        'read-only',
    ])->and($members)->toHaveCount(15)
        ->and(array_unique($members))->toHaveCount(15)
        ->and(p5eSorted($members))->toBe($inventory['commands']);

    $controlled = SystemAuthorityInventory::discover(
        [p5eProvider(), p5eFixtureProvider()],
        [dirname(__DIR__).'/src', __DIR__.'/Fixtures'],
    );
    expect(array_values(array_diff($controlled['commands'], $members)))
        ->toContain(UnclassifiedStateChangingCommand::class);
});

it('proves every cloud wrapper keeps the local-driver remote-execute hash-only boundary', function (): void {
    foreach ([OwnershipMintClaimCommand::class, OwnershipRemintOwnerTokenCommand::class] as $class) {
        $source = p5eSource($class);
        expect($source)->toContain(
            "option('execute')",
            "option('local')",
            'runner->run(',
            'escapeshellarg($generated->hash)',
            "return \$result['exitCode'];",
        );
        $remote = strstr($source, '$runner->run(') ?: '';
        expect(substr($remote, 0, (int) strpos($remote, ');')))->not->toContain('$generated->plaintext');
    }

    $createAdmin = p5eSource(CreateAdminCommand::class);
    expect($createAdmin)->toContain(
        "option('execute')",
        "option('local')",
        'runner->run(',
        '--password-hash=',
        'return escapeshellarg($value);',
        "return \$result['exitCode'];",
    )->not->toContain(".' --password='");
});

it('proves every local-only mutation refuses without the mandatory local flag', function (): void {
    foreach (p5eCommandDisposition()['local-only-mandatory-flag'] as $class) {
        expect(p5eSource($class))->toContain('if (! $this->requireLocal())');
    }

    expect(p5eSource(CredentialMintCommand::class))->toContain('use ParsesCredentialVerbInput;')
        ->and((string) file_get_contents(dirname(__DIR__).'/src/Commands/Concerns/ParsesCredentialVerbInput.php'))
        ->toContain('pass --local to act on this machine');
});

it('names the unchanged maintenance and install-scaffold behavior instead of excluding those commands', function (): void {
    foreach (p5eCommandDisposition()['in-environment-maintenance'] as $class) {
        $source = p5eSource($class);
        expect($source)->not->toContain('CloudCommandRunner', 'requireLocal()');
    }

    $install = p5eSource(InstallOperatorCredentialCommand::class);
    expect($install)->toContain('AuditActor::cliOperator()', 'MintCredential $mint')
        ->not->toContain('CloudCommandRunner', 'requireLocal()');
});

it('pins the advisory auth vocabulary to the framework contract subset it claims', function (): void {
    // This keeps the tripwire's documented contract subset honest. It does not
    // claim to enumerate SessionGuard or facade methods: runtime Authenticated +
    // Login enforcement carries that prohibition.
    $reflection = new ReflectionClass(SystemAuthorityInventory::class);
    $operations = $reflection->getConstant('AUTH_OPERATIONS');

    $declared = [];
    foreach ([StatefulGuard::class, Guard::class] as $contract) {
        foreach ((new ReflectionClass($contract))->getMethods() as $method) {
            $declared[] = $method->getName();
        }
    }

    // Deliberately excluded because none accepts an arbitrary new identity.
    // user() can restore a session or recaller identity, viaRemember() reports
    // restoration status, and logout() clears identity.
    $excluded = ['check', 'guest', 'user', 'id', 'hasUser', 'validate', 'logout', 'viaRemember'];

    expect(array_values(array_diff(array_unique($declared), $excluded)))
        ->toEqualCanonicalizing($operations);
});

it('reports an auth operation on a receiver it cannot establish instead of clearing it', function (): void {
    // app('auth') and resolve('auth') declare no class return type, so the
    // container can hand back the auth manager with nothing in the signature
    // saying so. Fail CLOSED, the way an unattributable schedule event is.
    $inventory = SystemAuthorityInventory::discover(
        [p5eProvider(), p5eFixtureProvider()],
        [dirname(__DIR__).'/src', __DIR__.'/Fixtures'],
    );

    expect($inventory['violations']['commands'])->toContain(
        'human-principal:'.RogueAttemptLoginCommand::class,
        'synthesized-human:'.RogueAttemptLoginCommand::class,
        'human-principal:'.RogueOnceUsingIdLoginCommand::class,
        'synthesized-human:'.RogueOnceUsingIdLoginCommand::class,
        'uninspectable-auth:'.RogueContainerAuthCommand::class,
    );
});

it('keeps the production inventory clean under the fail-closed auth rule', function (): void {
    // A fail-closed rule that flagged the package itself would be useless, so the
    // no-false-positive half is asserted here rather than assumed.
    $inventory = SystemAuthorityInventory::discover([p5eProvider()], [dirname(__DIR__).'/src']);

    expect($inventory['violations']['commands'])->toBe([])
        ->and($inventory['violations']['queued'])->toBe([])
        ->and($inventory['violations']['scheduled'])->toBe([]);
});
