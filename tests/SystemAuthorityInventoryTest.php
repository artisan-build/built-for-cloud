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
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RogueHumanQueuedJob;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RogueScheduleRegistration;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RogueUserPrincipalCommand;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RogueUserRoleCommand;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\UnclassifiedStateChangingCommand;

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
        RogueUserPrincipalCommand::class,
        RogueUserRoleCommand::class,
        UnclassifiedStateChangingCommand::class,
    )->and($inventory['violations']['commands'])->toContain(
        'human-principal:'.RogueUserPrincipalCommand::class,
        'human-role:'.RogueUserRoleCommand::class,
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

it('positive-controls the empty schedule inventory with a fixture registration', function (): void {
    $production = SystemAuthorityInventory::discover([p5eProvider()], [dirname(__DIR__).'/src']);
    $controlled = SystemAuthorityInventory::discover(
        [p5eProvider()],
        [dirname(__DIR__).'/src', __DIR__.'/Fixtures/RogueScheduleRegistration.php'],
    );

    expect($production['scheduled'])->toBe([])
        ->and($controlled['scheduled'])->toBe([RogueScheduleRegistration::class.'::schedule'])
        ->and($controlled['violations']['scheduled'])->toContain(
            'human-role:'.RogueScheduleRegistration::class,
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
