<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\RotateCredential;
use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\AuditReason;
use ArtisanBuild\BuiltForCloud\Contracts\AuthorizesCredentialVerbs;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\CredentialVerb;
use ArtisanBuild\BuiltForCloud\DurableStore;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\RotateOptions;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\Testing\DetectsSecretLeaks;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Process;

uses(RefreshDatabase::class, DetectsSecretLeaks::class);

/**
 * @return array{Authorization: string}
 */
function rotationAdminHeaders(): array
{
    $plaintext = 'rotation-admin-secret-'.bin2hex(random_bytes(8));

    ApiToken::query()->create([
        'name' => 'rotation-admin-'.bin2hex(random_bytes(4)),
        'token_hash' => hash('sha256', $plaintext),
        'abilities' => [Scope::Admin->value],
    ]);

    return ['Authorization' => 'Bearer '.$plaintext];
}

/**
 * @return list<string>
 */
function rotationEventsFor(string $credentialId): array
{
    $events = CredentialAuditEvent::query()
        ->where('credential_id', $credentialId)
        ->pluck('event')
        ->map(fn ($event): string => $event->value)
        ->values()
        ->all();

    sort($events);

    return $events;
}

/**
 * A rotatable source row: scoped, expiring, subject- and user-bound —
 * everything default rotation must preserve exactly.
 */
function rotatableSource(array $overrides = []): Credential
{
    return Credential::factory()->create(array_merge([
        'subject_ref' => 'acme',
        'name' => 'ci',
        'abilities' => ['consume'],
        'user_id' => '42',
        'expires_at' => now()->addDays(30),
    ], $overrides));
}

// -------------------------------------------------- default preservation (AC 3)

it('rotates by id via the CLI, preserving abilities, subject, user binding and remaining expiry exactly, leaking the secret nowhere', function (): void {
    Process::fake();

    $source = rotatableSource();
    $sourceExpiry = $source->expires_at;

    $output = $this->assertNoSecretLeakageOfMinted(
        function () use ($source): string {
            expect(Artisan::call('bfc:credential:rotate', ['id' => $source->id, '--local' => true]))->toBe(0);

            return Artisan::output();
        },
        function (string $output): ?string {
            return preg_match('/shown once: (\S+)/', $output, $matches) === 1 ? $matches[1] : null;
        },
    );

    Process::assertNothingRan();

    preg_match('/shown once: (\S+)/', $output, $matches);
    $secret = $matches[1];

    $this->assertRevealsSecretExactlyOnce($output, $secret);

    $replacement = Credential::query()->where('secret_hash', hash('sha256', $secret))->sole();

    expect($replacement->abilities)->toBe(['consume'])
        ->and($replacement->hasAbility('consume'))->toBeTrue()
        ->and($replacement->subject_type)->toBe($source->subject_type)
        ->and($replacement->subject_ref)->toBe('acme')
        ->and($replacement->user_id)->toBe('42')
        ->and($replacement->name)->toBe('ci')
        ->and($replacement->status)->toBe(CredentialStatus::Active)
        ->and($replacement->expires_at?->timestamp)->toBe($sourceExpiry?->timestamp)
        ->and($replacement->rotated_at)->toBeNull()
        ->and($output)->toContain('superseding '.$source->id);

    // The old row: stamped, granted the hour of grace, still resolvable.
    $source->refresh();

    expect($source->rotated_at)->not->toBeNull()
        ->and($source->expires_at?->greaterThan(now()->addMinutes(59)))->toBeTrue()
        ->and($source->expires_at?->lessThanOrEqualTo(now()->addHour()))->toBeTrue()
        ->and($source->revoked_at)->toBeNull();
});

// ------------------------------------------- make-before-break + grace (AC 4)

it('resolves both credentials through the grace window and only the replacement after it', function (): void {
    $source = rotatableSource(['expires_at' => null]);

    $response = $this->postJson('/bfc/credentials/'.$source->id.'/rotate', [], rotationAdminHeaders())
        ->assertCreated();

    $replacementId = (string) $response->json('credential.id');

    $resolvable = fn (): array => Credential::query()->active()->pluck('id')->all();

    expect($resolvable())->toContain($source->id, $replacementId);

    // At grace end the old row dies by its own expiry — no reaper ran.
    $this->travel(61)->minutes();

    expect($resolvable())->not->toContain($source->id)
        ->and($resolvable())->toContain($replacementId);
});

it('kills the old credential immediately under emergency and audits the emergency reason', function (): void {
    $source = rotatableSource(['expires_at' => null]);

    $this->postJson('/bfc/credentials/'.$source->id.'/rotate', ['emergency' => true], rotationAdminHeaders())
        ->assertCreated();

    $source->refresh();

    expect(Credential::query()->active()->pluck('id')->all())->not->toContain($source->id)
        ->and($source->rotated_at)->not->toBeNull();

    $rotated = CredentialAuditEvent::query()
        ->where('credential_id', $source->id)
        ->where('event', LifecycleEventType::Rotated->value)
        ->sole();

    expect($rotated->reason_code)->toBe(AuditReason::Emergency);
});

it('never extends a lifetime at cutover: a row expiring before grace end keeps its earlier death', function (): void {
    $source = rotatableSource(['expires_at' => now()->addMinutes(10)]);
    $sourceExpiry = $source->expires_at;

    $this->postJson('/bfc/credentials/'.$source->id.'/rotate', [], rotationAdminHeaders())->assertCreated();

    expect($source->refresh()->expires_at?->timestamp)->toBe($sourceExpiry?->timestamp);
});

// ----------------------------------------------- lineage + audit rows (AC 5)

it('stamps rotated_at and records the issued and rotated events with old-to-new lineage', function (): void {
    $source = rotatableSource();

    $response = $this->postJson('/bfc/credentials/'.$source->id.'/rotate', [], rotationAdminHeaders())
        ->assertCreated();

    $replacementId = (string) $response->json('credential.id');

    expect($response->json('superseded_id'))->toBe($source->id)
        ->and($source->refresh()->rotated_at)->not->toBeNull()
        ->and(rotationEventsFor($source->id))->toBe([LifecycleEventType::Rotated->value])
        ->and(rotationEventsFor($replacementId))->toBe([LifecycleEventType::Issued->value]);

    $rotated = CredentialAuditEvent::query()
        ->where('credential_id', $source->id)
        ->sole();

    expect($rotated->superseded_by_credential_id)->toBe($replacementId)
        ->and($rotated->reason_code)->toBe(AuditReason::Rotation);
});

it('shows old-in-grace beside new-active in the listing — the elsewhere-hosted case leaves nothing untracked', function (): void {
    $source = rotatableSource(['subject_ref' => 'manual-install', 'expires_at' => null]);

    $response = $this->postJson('/bfc/credentials/'.$source->id.'/rotate', [], rotationAdminHeaders())
        ->assertCreated();

    $replacementId = (string) $response->json('credential.id');

    $rows = collect($this->getJson('/bfc/credentials', rotationAdminHeaders())->assertOk()->json())
        ->keyBy('id');

    // The human installing by hand sees exactly the true state: the old
    // credential active in its grace window, stamped as superseded, and
    // the replacement active beside it.
    expect($rows[$source->id]['status'])->toBe('active')
        ->and($rows[$source->id]['rotated_at'])->not->toBeNull()
        ->and($rows[$replacementId]['status'])->toBe('active')
        ->and($rows[$replacementId]['rotated_at'])->toBeNull();
});

// ------------------------------------------------- refuse-on-ambiguity (AC 2)

it('refuses name-based rotation when two active rows share the name, naming the count, while by-id succeeds', function (): void {
    $first = rotatableSource(['name' => 'shared']);
    $second = rotatableSource(['name' => 'shared']);

    expect(Artisan::call('bfc:credential:rotate', ['--name' => 'shared', '--local' => true]))->toBe(1);

    $output = Artisan::output();

    expect($output)->toContain('2 resolvable credentials share the name "shared"')
        ->and($output)->toContain('Rotate by id')
        ->and($first->refresh()->rotated_at)->toBeNull()
        ->and($second->refresh()->rotated_at)->toBeNull();

    // By id: exactly the named row rotates; the same-named sibling is untouched.
    expect(Artisan::call('bfc:credential:rotate', ['id' => $first->id, '--local' => true]))->toBe(0)
        ->and($first->refresh()->rotated_at)->not->toBeNull()
        ->and($second->refresh()->rotated_at)->toBeNull();
});

it('rotates by name when exactly one active row carries it, and refuses an unknown name', function (): void {
    $only = rotatableSource(['name' => 'solo-name']);

    expect(Artisan::call('bfc:credential:rotate', ['--name' => 'solo-name', '--local' => true]))->toBe(0)
        ->and($only->refresh()->rotated_at)->not->toBeNull();

    expect(Artisan::call('bfc:credential:rotate', ['--name' => 'ghost', '--local' => true]))->toBe(1)
        ->and(Artisan::output())->toContain('No resolvable credential is named "ghost"');
});

it('requires exactly one target: an id or --name, never both, never neither', function (): void {
    $source = rotatableSource();

    expect(Artisan::call('bfc:credential:rotate', ['id' => $source->id, '--name' => 'ci', '--local' => true]))->toBe(1)
        ->and(Artisan::output())->toContain('exactly one target');

    expect(Artisan::call('bfc:credential:rotate', ['--local' => true]))->toBe(1)
        ->and(Artisan::output())->toContain('exactly one target');
});

// ------------------------------------------------- override discipline (AC 3)

it('refuses a widening attempt without the override flag, identically on both transports', function (): void {
    $cliSource = rotatableSource();
    $httpSource = rotatableSource();

    expect(Artisan::call('bfc:credential:rotate', [
        'id' => $cliSource->id,
        '--abilities' => 'consume,admin',
        '--local' => true,
    ]))->toBe(1);
    $cliMessage = trim(Artisan::output());

    $httpResponse = $this->postJson('/bfc/credentials/'.$httpSource->id.'/rotate', [
        'abilities' => ['consume', 'admin'],
    ], rotationAdminHeaders())->assertStatus(422);

    expect($cliMessage)->toBe((string) $httpResponse->json('message'))
        ->and($cliMessage)->toContain('override')
        ->and($cliSource->refresh()->rotated_at)->toBeNull()
        ->and($httpSource->refresh()->rotated_at)->toBeNull()
        ->and(Credential::query()->count())->toBe(2);
});

it('refuses narrowing without the flag too: predictability beats cleverness', function (): void {
    $source = rotatableSource(['abilities' => ['consume', 'read']]);

    $this->postJson('/bfc/credentials/'.$source->id.'/rotate', [
        'abilities' => ['consume'],
    ], rotationAdminHeaders())->assertStatus(422);

    expect($source->refresh()->rotated_at)->toBeNull()
        ->and(Credential::query()->count())->toBe(1);
});

it('refuses the override flag with nothing to override', function (): void {
    $source = rotatableSource();

    $response = $this->postJson('/bfc/credentials/'.$source->id.'/rotate', [
        'override' => true,
    ], rotationAdminHeaders())->assertStatus(422);

    expect((string) $response->json('message'))->toContain('nothing to override');
});

it('performs a flagged override as its own matrix consultation with the delta visible, and audits reason plus delta', function (): void {
    $consultations = new ArrayObject;

    app()->bind(CredentialDeclaration::class, function () use ($consultations): CredentialDeclaration {
        return new class($consultations) implements AuthorizesCredentialVerbs, CredentialDeclaration
        {
            public function __construct(private readonly ArrayObject $consultations) {}

            public function resolveSubject(Request $request): ?Subject
            {
                return null;
            }

            public function authorize(Credential $credential, ?string $ability, Request $request): bool
            {
                return true;
            }

            public function authorizeVerb(CredentialVerb $verb, ?Subject $subject, Request $request): bool
            {
                $this->consultations->append([
                    'verb' => $verb->value,
                    'override' => $request->attributes->get(RotateCredential::OVERRIDE_CONTEXT_ATTRIBUTE),
                ]);

                return true;
            }
        };
    });

    $source = rotatableSource();

    $response = $this->postJson('/bfc/credentials/'.$source->id.'/rotate', [
        'override' => true,
        'abilities' => ['consume', 'admin'],
    ], rotationAdminHeaders())->assertCreated();

    $replacement = Credential::query()->findOrFail((string) $response->json('credential.id'));

    expect($replacement->abilities)->toBe(['consume', 'admin']);

    // Two rotate consultations: the routine one (no override context) and
    // the override's OWN, with the delta visible in the request context.
    $rotateConsultations = array_values(array_filter(
        $consultations->getArrayCopy(),
        fn (array $c): bool => $c['verb'] === 'rotate',
    ));

    expect($rotateConsultations)->toHaveCount(2)
        ->and($rotateConsultations[0]['override'])->toBeNull()
        ->and($rotateConsultations[1]['override'])->toBe([
            'abilities' => ['consume', 'admin'],
            'expires_at' => null,
        ]);

    // And the context attribute does not linger past the consultation.
    expect(app('request')->attributes->has(RotateCredential::OVERRIDE_CONTEXT_ATTRIBUTE))->toBeFalse();

    $rotated = CredentialAuditEvent::query()
        ->where('credential_id', $source->id)
        ->where('event', LifecycleEventType::Rotated->value)
        ->sole();

    expect($rotated->reason_code)->toBe(AuditReason::Override)
        ->and((string) $rotated->note)->toContain('abilities')
        ->and((string) $rotated->note)->toContain('admin');
});

it('lets a declaration deny exactly the override while allowing routine rotation', function (): void {
    app()->bind(CredentialDeclaration::class, fn (): CredentialDeclaration => new class implements AuthorizesCredentialVerbs, CredentialDeclaration
    {
        public function resolveSubject(Request $request): ?Subject
        {
            return null;
        }

        public function authorize(Credential $credential, ?string $ability, Request $request): bool
        {
            return true;
        }

        public function authorizeVerb(CredentialVerb $verb, ?Subject $subject, Request $request): bool
        {
            return ! $request->attributes->has(RotateCredential::OVERRIDE_CONTEXT_ATTRIBUTE);
        }
    });

    $source = rotatableSource();

    $refusal = $this->postJson('/bfc/credentials/'.$source->id.'/rotate', [
        'override' => true,
        'abilities' => ['consume', 'admin'],
    ], rotationAdminHeaders())->assertForbidden();

    expect((string) $refusal->json('message'))->toContain('denies this rotation override')
        ->and($source->refresh()->rotated_at)->toBeNull()
        ->and(Credential::query()->count())->toBe(1);

    // The routine path is untouched by the denial.
    $this->postJson('/bfc/credentials/'.$source->id.'/rotate', [], rotationAdminHeaders())->assertCreated();
});

// ------------------------------------------------------- per-kind (AC 6)

it('rotates a basic credential into a fresh auth.json pair', function (): void {
    $source = rotatableSource(['kind' => CredentialKind::Basic]);

    $response = $this->postJson('/bfc/credentials/'.$source->id.'/rotate', [], rotationAdminHeaders())
        ->assertCreated();

    $replacementId = (string) $response->json('credential.id');

    expect($response->json('delivery.shape'))->toBe('basic_auth')
        ->and($response->json('delivery.username'))->toBe($replacementId)
        ->and(Credential::query()->findOrFail($replacementId)->secret_hash)
        ->toBe(hash('sha256', (string) $response->json('delivery.password')));
});

it('rotates an asymmetric credential into a fresh enrollment code with both credentials active through grace', function (): void {
    $source = Credential::factory()->asymmetric()->create([
        'subject_ref' => 'reel-like',
        'name' => 'signer',
        'abilities' => ['consume'],
        'expires_at' => null,
    ]);

    $response = $this->postJson('/bfc/credentials/'.$source->id.'/rotate', [
        'code_ttl_seconds' => 3600,
    ], rotationAdminHeaders())->assertCreated();

    $replacementId = (string) $response->json('credential.id');
    $replacement = Credential::query()->findOrFail($replacementId);

    expect($response->json('delivery.shape'))->toBe('enrollment_code')
        ->and((string) $response->json('delivery.enrollment_code'))->not->toBe('')
        ->and($replacement->kind)->toBe(CredentialKind::Asymmetric)
        ->and($replacement->status)->toBe(CredentialStatus::Pending)
        ->and($replacement->secret_hash)->toBeNull()
        ->and($replacement->public_key)->toBeNull()
        ->and($replacement->abilities)->toBe(['consume']);

    // The code is a claim-primitive row linked to the pending replacement.
    $code = OnboardingToken::query()
        ->where('durable_token_id', $replacementId)
        ->where('durable_store', DurableStore::Credentials->value)
        ->sole();

    expect($code->token_hash)->toBe(hash('sha256', (string) $response->json('delivery.enrollment_code')));

    // The OLD keypair keeps verifying through the grace window: its public
    // key is still among the subject's active keys, beside the pending row.
    $source->refresh();

    expect($source->status)->toBe(CredentialStatus::Active)
        ->and($source->rotated_at)->not->toBeNull()
        ->and($source->expires_at?->greaterThan(now()->addMinutes(59)))->toBeTrue()
        ->and(Credential::activePublicKeysFor($source->subject_type, 'reel-like'))->toBe([$source->public_key]);
});

it('requires the enrollment-code ttl when rotating an asymmetric credential', function (): void {
    $source = Credential::factory()->asymmetric()->create();

    $response = $this->postJson('/bfc/credentials/'.$source->id.'/rotate', [], rotationAdminHeaders())
        ->assertStatus(422);

    expect((string) $response->json('message'))->toContain('ttl is required')
        ->and($source->refresh()->rotated_at)->toBeNull();
});

it('refuses hmac rotation explicitly, naming the pending-then-activate work, identically on both transports', function (): void {
    $cliSource = Credential::factory()->create(['kind' => CredentialKind::Hmac]);
    $httpSource = Credential::factory()->create(['kind' => CredentialKind::Hmac]);

    expect(Artisan::call('bfc:credential:rotate', ['id' => $cliSource->id, '--local' => true]))->toBe(1);
    $cliMessage = trim(Artisan::output());

    $httpResponse = $this->postJson('/bfc/credentials/'.$httpSource->id.'/rotate', [], rotationAdminHeaders())
        ->assertForbidden();

    expect($cliMessage)->toBe((string) $httpResponse->json('message'))
        ->and($cliMessage)->toContain('"hmac" credential kind does not rotate')
        ->and($cliMessage)->toContain('pending')
        ->and($cliSource->refresh()->rotated_at)->toBeNull()
        ->and(Credential::query()->count())->toBe(2);
});

// -------------------------------------------------- unrotatable sources

it('refuses to rotate revoked, expired and pending rows with a 409 naming the state', function (): void {
    $revoked = Credential::factory()->revoked()->create();
    $expired = Credential::factory()->expired()->create();
    $pending = Credential::factory()->asymmetric()->pending()->create();

    $headers = rotationAdminHeaders();

    expect((string) $this->postJson('/bfc/credentials/'.$revoked->id.'/rotate', [], $headers)
        ->assertStatus(409)->json('message'))->toContain('revoked');

    expect((string) $this->postJson('/bfc/credentials/'.$expired->id.'/rotate', [], $headers)
        ->assertStatus(409)->json('message'))->toContain('expired');

    expect((string) $this->postJson('/bfc/credentials/'.$pending->id.'/rotate', [], $headers)
        ->assertStatus(409)->json('message'))->toContain('pending enrollment');

    $this->postJson('/bfc/credentials/no-such-id/rotate', [], $headers)->assertNotFound();

    expect(Credential::query()->count())->toBe(3);
});

// ------------------------------------------------- failure path A (AC 7)

it('rolls the whole rotation back when a follow-up write fails, leaving no orphan, and a retry succeeds', function (): void {
    $source = rotatableSource();

    // Force the FOLLOW-UP write (the rotated lineage event) to fail at the
    // database, inside the mint's own transaction.
    DB::statement("CREATE TRIGGER bfc_fail_rotated_event BEFORE INSERT ON credential_audit_events WHEN NEW.event = 'rotated' BEGIN SELECT RAISE(ABORT, 'forced lineage failure'); END");

    $rotate = app(RotateCredential::class);

    try {
        $rotate($source->id, RotateOptions::fromInput([]));
        $this->fail('The forced lineage failure did not surface.');
    } catch (QueryException) {
        // The failure the trigger forced.
    }

    // Rollback is COMPLETE: no orphan credential, no stamp, no audit rows,
    // and the source is exactly as it was.
    $source->refresh();

    expect(Credential::query()->count())->toBe(1)
        ->and($source->rotated_at)->toBeNull()
        ->and($source->abilities)->toBe(['consume'])
        ->and(CredentialAuditEvent::query()->count())->toBe(0);

    // Retry works once the failure clears.
    DB::statement('DROP TRIGGER bfc_fail_rotated_event');

    $result = $rotate($source->id, RotateOptions::fromInput([]));

    expect($result)->not->toBeNull()
        ->and(Credential::query()->count())->toBe(2)
        ->and($source->refresh()->rotated_at)->not->toBeNull();
});

// ------------------------------------------------- failure path B (AC 8)

it('leaves the replacement standing when old-row retirement fails, names the leftover id, and revoke-by-id can always kill it', function (): void {
    $source = rotatableSource(['expires_at' => null]);

    // Fail exactly the cutover write: phase 1 touches only rotated_at, so
    // this trigger lets the mint transaction commit and aborts the
    // expiry-set that follows.
    DB::statement("CREATE TRIGGER bfc_fail_cutover BEFORE UPDATE OF expires_at ON credentials WHEN NEW.rotated_at IS NOT NULL BEGIN SELECT RAISE(ABORT, 'forced cutover failure'); END");

    $response = $this->postJson('/bfc/credentials/'.$source->id.'/rotate', [], rotationAdminHeaders())
        ->assertStatus(500);

    $message = (string) $response->json('message');

    // The error names the leftover row (and the standing replacement); no
    // secret was delivered anywhere in the response.
    expect($message)->toContain($source->id)
        ->and($message)->toContain('STILL LIVE')
        ->and($response->json('delivery'))->toBeNull();

    $replacement = Credential::query()->whereKeyNot($source->id)->sole();

    expect($message)->toContain($replacement->id)
        ->and($replacement->status)->toBe(CredentialStatus::Active)
        ->and($replacement->abilities)->toBe(['consume']);

    // The old row: still live, visible with its stamp — and the anomaly-
    // repair semantics hold: revoke-by-id can always kill it.
    $source->refresh();

    expect($source->rotated_at)->not->toBeNull()
        ->and($source->expires_at)->toBeNull()
        ->and(Credential::query()->active()->pluck('id')->all())->toContain($source->id);

    DB::statement('DROP TRIGGER bfc_fail_cutover');

    $this->deleteJson('/bfc/credentials/'.$source->id, [], rotationAdminHeaders())->assertNoContent();

    expect(Credential::query()->active()->pluck('id')->all())->not->toContain($source->id);
});

// --------------------------------------- HTTP delivery containment (D7)

it('reveals the HTTP rotation secret exactly once and leaks it into no side-effect channel', function (): void {
    $source = rotatableSource();

    $response = $this->assertNoSecretLeakageOfMinted(
        fn () => $this->postJson('/bfc/credentials/'.$source->id.'/rotate', [], rotationAdminHeaders()),
        fn ($response): ?string => $response->json('delivery.secret'),
    );

    $response->assertCreated();

    $this->assertRevealsSecretExactlyOnce((string) $response->getContent(), (string) $response->json('delivery.secret'));
});

// ------------------------------------------------------- gate + matrix

it('keeps the rotate route behind the credential-admin gate', function (): void {
    $source = rotatableSource();

    $this->postJson('/bfc/credentials/'.$source->id.'/rotate')->assertUnauthorized();

    expect($source->refresh()->rotated_at)->toBeNull();
});

it('refuses rotation identically on both transports when the matrix denies the verb', function (): void {
    app()->bind(CredentialDeclaration::class, fn (): CredentialDeclaration => new class implements AuthorizesCredentialVerbs, CredentialDeclaration
    {
        public function resolveSubject(Request $request): ?Subject
        {
            return null;
        }

        public function authorize(Credential $credential, ?string $ability, Request $request): bool
        {
            return true;
        }

        public function authorizeVerb(CredentialVerb $verb, ?Subject $subject, Request $request): bool
        {
            return $verb !== CredentialVerb::Rotate;
        }
    });

    $cliSource = rotatableSource();
    $httpSource = rotatableSource();

    expect(Artisan::call('bfc:credential:rotate', ['id' => $cliSource->id, '--local' => true]))->toBe(1);
    $cliMessage = trim(Artisan::output());

    $httpResponse = $this->postJson('/bfc/credentials/'.$httpSource->id.'/rotate', [], rotationAdminHeaders())
        ->assertForbidden();

    expect($cliMessage)->toBe((string) $httpResponse->json('message'))
        ->and($cliMessage)->toContain('denies the rotate verb')
        ->and(Credential::query()->count())->toBe(2);
});
