<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuditActorType;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\Ownership;
use ArtisanBuild\BuiltForCloud\OwnershipClaim;
use ArtisanBuild\BuiltForCloud\Testing\DetectsSecretLeaks;
use Illuminate\Console\Command;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Process;

uses(RefreshDatabase::class, DetectsSecretLeaks::class);

// Locked AC 5: the credential commands run with --local against the local
// database and NO Cloud binary — Process::fake() + assertNothingRan() is
// the "no Cloud dependency" proof on every path here.

beforeEach(function (): void {
    Process::fake();
});

it('mints a credential locally with --local, printing the secret once and emitting issued', function (): void {
    $output = $this->assertNoSecretLeakageOfMinted(
        function (): string {
            expect(Artisan::call('bfc:credential:mint', [
                'subject-type' => 'application',
                'subject-ref' => 'local-app',
                '--name' => 'local-app',
                '--abilities' => 'consume',
                '--local' => true,
            ]))->toBe(Command::SUCCESS);

            return Artisan::output();
        },
        function (string $output): string {
            preg_match('/shown once: (\S+)/', $output, $matches);

            return $matches[1] ?? '';
        },
    );

    preg_match('/shown once: (\S+)/', $output, $matches);
    $plaintext = $matches[1];

    $this->assertRevealsSecretExactlyOnce($output, $plaintext);

    $token = Credential::query()->where('name', 'local-app')->sole();

    expect($token->secret_hash)->toBe(hash('sha256', $plaintext))
        ->and($token->abilities)->toBe(['consume']);

    // The mint appears in the lifecycle stream.
    $event = CredentialAuditEvent::query()->where('credential_id', $token->getKey())->sole();

    expect($event->event)->toBe(LifecycleEventType::Issued)
        ->and($event->actor_type)->toBe(AuditActorType::CliOperator);

    Process::assertNothingRan();
});

it('lists credentials locally with --local', function (): void {
    Credential::factory()->create(['name' => 'listable']);

    expect(Artisan::call('bfc:credential:list', ['--local' => true]))->toBe(Command::SUCCESS)
        ->and(Artisan::output())->toContain('listable');

    Process::assertNothingRan();
});

it('revokes a credential locally with --local', function (): void {
    $doomed = Credential::factory()->create(['name' => 'doomed']);

    expect(Artisan::call('bfc:credential:revoke', ['id' => $doomed->id, '--local' => true]))->toBe(Command::SUCCESS)
        ->and(Artisan::output())->toContain('Revoked credential');

    expect($doomed->refresh()->revoked_at)->not->toBeNull();

    Process::assertNothingRan();
});

it('rotates a credential locally with --local, printing the replacement once with an hour of grace', function (): void {
    $old = Credential::factory()->create(['name' => 'rotating']);

    expect(Artisan::call('bfc:credential:rotate', ['id' => $old->id, '--local' => true]))->toBe(Command::SUCCESS);

    $output = Artisan::output();

    preg_match('/shown once: (\S+)/', $output, $matches);
    $plaintext = $matches[1];

    expect(substr_count($output, $plaintext))->toBe(1)
        ->and($output)->toContain('grace window (one hour)');

    $replacement = Credential::query()->where('secret_hash', hash('sha256', $plaintext))->sole();

    expect($replacement->name)->toBe('rotating')
        ->and($old->refresh()->rotated_at)->not->toBeNull()
        ->and($old->expires_at->timestamp)->toBeGreaterThan(now()->addMinutes(55)->timestamp);

    Process::assertNothingRan();
});

it('mints an ownership claim locally with --local, printing the claim token once', function (): void {
    expect(Artisan::call('bfc:ownership:mint-claim', ['--local' => true]))->toBe(Command::SUCCESS);

    $output = Artisan::output();

    preg_match('/shown once: (\S+)/', $output, $matches);
    $plaintext = $matches[1];

    expect(substr_count($output, $plaintext))->toBe(1)
        ->and(OwnershipClaim::query()->where('token_hash', OwnershipClaim::hashToken($plaintext))->exists())->toBeTrue();

    Process::assertNothingRan();
});

it('refuses to mint a claim locally when ownership is already claimed', function (): void {
    $credential = Credential::factory()->create(['name' => 'owner']);
    Ownership::query()->create(['owner_credential_id' => $credential->getKey()]);

    expect(Artisan::call('bfc:ownership:mint-claim', ['--local' => true]))->toBe(Command::FAILURE)
        ->and(Artisan::output())->toContain('already claimed');

    Process::assertNothingRan();
});

it('remints the owner credential locally with --local, revoking the previous owner row', function (): void {
    $old = Credential::factory()->create(['name' => 'linked-owner']);
    Ownership::query()->create(['owner_credential_id' => $old->getKey()]);

    expect(Artisan::call('bfc:ownership:remint-owner-token', ['--local' => true]))->toBe(Command::SUCCESS);

    $output = Artisan::output();

    preg_match('/shown once: (\S+)/', $output, $matches);
    $plaintext = $matches[1];

    $replacement = Credential::query()->where('secret_hash', hash('sha256', $plaintext))->sole();

    expect(substr_count($output, $plaintext))->toBe(1)
        ->and($replacement->abilities)->toBe([EnsureCredentialAdmin::ABILITY])
        ->and(Ownership::query()->sole()->owner_credential_id)->toBe((string) $replacement->getKey())
        ->and($old->refresh()->revoked_at)->not->toBeNull();

    Process::assertNothingRan();
});

// Locked AC 6: no new or changed command accepts a secret as an argument —
// the surface itself is tested, not just the behaviour. (The one command
// LIMITATION, stated honestly: this is a BLACKLIST of secret-shaped input
// names, so it catches a future option that NAMES itself like a secret,
// not one that smuggles a secret under an innocent name ("--value",
// "--data"). The real guarantee is D7's rule enforced in review and by
// the leak-harness tests on each command's behaviour; this test is the
// tripwire, not the proof.

it('accepts no secret-bearing argument or option on any new or changed command surface', function (): void {
    $commands = [
        'bfc:credential:mint',
        'bfc:credential:list',
        'bfc:credential:revoke',
        'bfc:credential:rotate',
        'bfc:credential:activate',
        'bfc:install:operator-credential',
        'bfc:ownership:mint-claim',
        'bfc:ownership:remint-owner-token',
    ];

    $forbidden = [
        'secret', 'password', 'plaintext', 'credential', 'private-key',
        'token', 'bearer', 'claim-code', 'key', 'auth',
    ];

    foreach ($commands as $name) {
        $definition = Artisan::all()[$name]->getDefinition();

        $inputs = [
            ...array_keys($definition->getArguments()),
            ...array_keys($definition->getOptions()),
        ];

        expect(array_intersect($inputs, $forbidden))->toBe([], "The {$name} command exposes a secret-accepting input.");
    }
});
