<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuditActorType;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\DetectsSecretLeaks;
use ArtisanBuild\BuiltForCloud\Testing\WithCredentials;
use Illuminate\Console\Command;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Process;

uses(RefreshDatabase::class, DetectsSecretLeaks::class, WithCredentials::class);

// Locked AC 7: the install scaffold path mints a real operator-subject
// credential printed once and stored only as a digest.

it('mints a real operator-subject credential at install time and prints it once', function (): void {
    Process::fake();

    $output = $this->assertNoSecretLeakageOfMinted(
        function (): string {
            expect(Artisan::call('bfc:install:operator-credential'))->toBe(Command::SUCCESS);

            return Artisan::output();
        },
        function (string $output): string {
            preg_match('/shown once: (\S+)/', $output, $matches);

            return $matches[1] ?? '';
        },
    );

    preg_match('/shown once: (\S+)/', $output, $matches);
    $secret = $matches[1];

    $this->assertRevealsSecretExactlyOnce($output, $secret);

    $credential = Credential::query()->sole();

    expect($credential->subject_type)->toBe(SubjectType::Operator)
        ->and($credential->subject_ref)->toBe('installer')
        ->and($credential->kind)->toBe(CredentialKind::Bearer)
        // The admin-equivalent ability the /bfc/credentials gate honours.
        ->and($credential->abilities)->toBe([EnsureCredentialAdmin::ABILITY])
        // Revocation-on-event, never a clock: no expiry is stamped.
        ->and($credential->expires_at)->toBeNull()
        ->and($credential->secret_hash)->toBe(hash('sha256', $secret));

    // A REAL credential: it appears in the lifecycle stream…
    $event = CredentialAuditEvent::query()->where('credential_id', $credential->id)->sole();

    expect($event->event)->toBe(LifecycleEventType::Issued)
        ->and($event->actor_type)->toBe(AuditActorType::CliOperator);

    // …and it is revocable, which no env pseudo-credential ever was.
    expect(Artisan::call('bfc:credential:revoke', ['id' => $credential->id, '--local' => true]))->toBe(Command::SUCCESS)
        ->and($credential->refresh()->revoked_at)->not->toBeNull();

    Process::assertNothingRan();
});

// Fix 1: the exact install-then-call flow — the printed credential must
// work on the surface it exists to manage, from the moment it is printed.

it('authorizes the freshly installed operator credential on the /bfc/credentials verbs', function (): void {
    Artisan::call('bfc:install:operator-credential');

    preg_match('/shown once: (\S+)/', Artisan::output(), $matches);
    $secret = $matches[1];
    $headers = ['Authorization' => 'Bearer '.$secret];

    // The install-minted secret drives a mint over HTTP…
    $response = $this->postJson('/bfc/credentials', [
        'subject_type' => 'external_consumer',
        'subject_ref' => 'first-customer',
        'abilities' => ['consume'],
    ], $headers)->assertCreated();

    // …audited as the unified-store actor, reflecting WHICH store
    // authenticated (never mistaken for a legacy admin token).
    $mintedId = (string) $response->json('credential.id');
    $operatorId = Credential::query()->where('subject_type', SubjectType::Operator->value)->sole()->id;

    $event = CredentialAuditEvent::query()->where('credential_id', $mintedId)->sole();

    expect($event->actor_type)->toBe(AuditActorType::OperatorIntegration)
        ->and($event->actor_ref)->toBe($operatorId);

    // The listing and the precise revoke answer to it too.
    $this->getJson('/bfc/credentials', $headers)->assertOk();
    $this->deleteJson('/bfc/credentials/'.$mintedId, [], $headers)->assertNoContent();

    // Presenting it was a use: the operator row carries the stamp.
    expect(Credential::query()->whereKey($operatorId)->sole()->last_used_at)->not->toBeNull();
});

it('refuses a non-operator unified credential on the /bfc/credentials verbs', function (): void {
    // Right ability, wrong subject: possession of the ability string on a
    // non-operator subject grants nothing.
    $nonOperator = $this->mintCredential([
        'subject_type' => SubjectType::ExternalConsumer,
        'subject_ref' => 'not-an-operator',
        'abilities' => [EnsureCredentialAdmin::ABILITY],
    ]);

    $this->getJson('/bfc/credentials', ['Authorization' => $nonOperator->bearerHeader()])->assertForbidden();

    // Right subject, missing ability: same refusal.
    $unableOperator = $this->mintCredential([
        'subject_type' => SubjectType::Operator,
        'subject_ref' => 'powerless',
        'abilities' => ['consume'],
    ]);

    $this->getJson('/bfc/credentials', ['Authorization' => $unableOperator->bearerHeader()])->assertForbidden();

    // A secret that resolves nothing stays 401.
    $this->getJson('/bfc/credentials', ['Authorization' => 'Bearer tok_'.str_repeat('0', 64)])->assertUnauthorized();
});

it('skips the mint with a notice when a live operator credential exists, unless forced', function (): void {
    expect(Artisan::call('bfc:install:operator-credential'))->toBe(Command::SUCCESS)
        ->and(Credential::query()->count())->toBe(1);

    expect(Artisan::call('bfc:install:operator-credential'))->toBe(Command::SUCCESS);

    $output = Artisan::output();

    expect($output)->toContain('already exists; skipping the install mint')
        ->and($output)->not->toContain('shown once')
        ->and(Credential::query()->count())->toBe(1);

    // Deliberate second operator credentials stay first-class (GATE-3).
    expect(Artisan::call('bfc:install:operator-credential', ['--force' => true]))->toBe(Command::SUCCESS)
        ->and(Credential::query()->count())->toBe(2);

    // A REVOKED operator credential does not block a fresh install mint.
    Credential::query()->update(['revoked_at' => now()]);

    expect(Artisan::call('bfc:install:operator-credential'))->toBe(Command::SUCCESS)
        ->and(Credential::query()->count())->toBe(3);
});

it('mints despite an existing operator that lacks the promised ability — mere operator existence is not the predicate', function (): void {
    // An operator credential WITHOUT credential:admin cannot manage the
    // credential verbs, so it does not satisfy the scaffold's promise.
    $this->mintCredential([
        'subject_type' => SubjectType::Operator,
        'subject_ref' => 'powerless',
        'abilities' => ['consume'],
    ]);

    expect(Artisan::call('bfc:install:operator-credential'))->toBe(Command::SUCCESS);

    $output = Artisan::output();

    expect($output)->toContain('shown once')
        ->and(Credential::query()->count())->toBe(2);

    // The freshly minted one carries the promised authority.
    $usable = Credential::query()
        ->where('subject_ref', 'installer')
        ->sole();

    expect($usable->hasAbility(EnsureCredentialAdmin::ABILITY))->toBeTrue();

    // And now that a USABLE operator exists, the re-run skips.
    expect(Artisan::call('bfc:install:operator-credential'))->toBe(Command::SUCCESS)
        ->and(Artisan::output())->toContain('skipping the install mint')
        ->and(Credential::query()->count())->toBe(2);
});

it('honours a custom operator ref and abilities', function (): void {
    Artisan::call('bfc:install:operator-credential', [
        '--ref' => 'scalpels',
        '--name' => 'Scalpels control plane',
        '--abilities' => 'admin,consume',
    ]);

    $credential = Credential::query()->sole();

    expect($credential->subject_ref)->toBe('scalpels')
        ->and($credential->name)->toBe('Scalpels control plane')
        ->and($credential->abilities)->toBe(['admin', 'consume']);
});
