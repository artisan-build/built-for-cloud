<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\AuditActorType;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\Ownership;
use ArtisanBuild\BuiltForCloud\OwnershipClaim;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\Testing\DetectsSecretLeaks;
use Illuminate\Console\Command;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Process;

uses(RefreshDatabase::class, DetectsSecretLeaks::class);

// Locked AC 5: all seven legacy commands run with --local against the local
// database and NO Cloud binary — Process::fake() + assertNothingRan() is
// the "no Cloud dependency" proof on every path here.

beforeEach(function (): void {
    Process::fake();
});

it('creates a token locally with --local, printing the secret once and emitting issued', function (): void {
    $output = $this->assertNoSecretLeakageOfMinted(
        function (): string {
            expect(Artisan::call('token:create', [
                'name' => 'local-app',
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

    $token = ApiToken::query()->where('name', 'local-app')->sole();

    expect($token->token_hash)->toBe(hash('sha256', $plaintext))
        ->and($token->abilities)->toBe(['consume']);

    // The issued gap, closed (PRD 1.16 ride-along): the legacy mint now
    // appears in the lifecycle stream.
    $event = CredentialAuditEvent::query()->where('credential_id', $token->getKey())->sole();

    expect($event->event)->toBe(LifecycleEventType::Issued)
        ->and($event->actor_type)->toBe(AuditActorType::CliOperator);

    Process::assertNothingRan();
});

it('emits issued from the execute half of token:create too', function (): void {
    $hash = hash('sha256', 'execute-secret');

    Artisan::call('token:create', ['name' => 'exec-app', '--execute' => true, '--hash' => $hash]);

    $token = ApiToken::query()->where('name', 'exec-app')->sole();

    expect(
        CredentialAuditEvent::query()
            ->where('credential_id', $token->getKey())
            ->where('event', LifecycleEventType::Issued->value)
            ->exists(),
    )->toBeTrue();
});

it('lists tokens locally with --local', function (): void {
    ApiToken::factory()->create(['name' => 'listable']);

    expect(Artisan::call('token:list', ['--local' => true]))->toBe(Command::SUCCESS)
        ->and(Artisan::output())->toContain('listable');

    Process::assertNothingRan();
});

it('revokes tokens locally with --local', function (): void {
    ApiToken::factory()->create(['name' => 'doomed']);

    expect(Artisan::call('token:revoke', ['name' => 'doomed', '--local' => true]))->toBe(Command::SUCCESS)
        ->and(Artisan::output())->toContain('Revoked 1 active row(s) for doomed');

    expect(ApiToken::query()->where('name', 'doomed')->sole()->revoked_at)->not->toBeNull();

    Process::assertNothingRan();
});

it('rotates a token locally with --local, printing the replacement once with an hour of grace', function (): void {
    $old = ApiToken::factory()->create(['name' => 'rotating']);

    expect(Artisan::call('token:rotate', ['name' => 'rotating', '--local' => true]))->toBe(Command::SUCCESS);

    $output = Artisan::output();

    preg_match('/shown once: (\S+)/', $output, $matches);
    $plaintext = $matches[1];

    expect(substr_count($output, $plaintext))->toBe(1)
        ->and($output)->toContain('one hour grace');

    $replacement = ApiToken::query()->where('token_hash', hash('sha256', $plaintext))->sole();

    expect($replacement->name)->toBe('rotating')
        ->and($old->refresh()->rotated_at)->not->toBeNull()
        ->and($old->expires_at->timestamp)->toBeGreaterThan(now()->addMinutes(55)->timestamp);

    Process::assertNothingRan();
});

it('reports token usage locally with --local', function (): void {
    ApiToken::factory()->create(['name' => 'busy', 'request_count' => 7]);

    expect(Artisan::call('token:usage', ['--local' => true]))->toBe(Command::SUCCESS)
        ->and(Artisan::output())->toContain('busy');

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
    $token = ApiToken::factory()->create(['name' => 'owner', 'abilities' => [Scope::Admin->value]]);
    Ownership::query()->create(['owner_token_id' => $token->getKey()]);

    expect(Artisan::call('bfc:ownership:mint-claim', ['--local' => true]))->toBe(Command::FAILURE)
        ->and(Artisan::output())->toContain('already claimed');

    Process::assertNothingRan();
});

it('remints the owner token locally with --local, revoking the previous owner row', function (): void {
    $old = ApiToken::factory()->create(['name' => 'owner', 'abilities' => [Scope::Admin->value]]);
    Ownership::query()->create(['owner_token_id' => $old->getKey()]);

    expect(Artisan::call('bfc:ownership:remint-owner-token', ['--local' => true]))->toBe(Command::SUCCESS);

    $output = Artisan::output();

    preg_match('/shown once: (\S+)/', $output, $matches);
    $plaintext = $matches[1];

    $replacement = ApiToken::query()->where('token_hash', hash('sha256', $plaintext))->sole();

    expect(substr_count($output, $plaintext))->toBe(1)
        ->and($replacement->abilities)->toBe([Scope::Admin->value])
        ->and(Ownership::query()->sole()->owner_token_id)->toBe((string) $replacement->getKey())
        ->and($old->refresh()->revoked_at)->not->toBeNull();

    Process::assertNothingRan();
});

// Locked AC 6: no new or changed command accepts a secret as an argument —
// the surface itself is tested, not just the behaviour. (The one command
// with a secret-shaped argument, bfc:token:revoke-self, REFUSES it; that
// refusal is pinned by its own suite.)
//
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
        'bfc:install:operator-credential',
        'token:create',
        'token:list',
        'token:revoke',
        'token:rotate',
        'token:usage',
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
