<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\RotateCredential;
use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\AuditReason;
use ArtisanBuild\BuiltForCloud\Contracts\AuthorizesCredentialVerbs;
use ArtisanBuild\BuiltForCloud\Contracts\AuthorizesRotationOverrides;
use ArtisanBuild\BuiltForCloud\Contracts\ConstrainsMintedCredentials;
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
use ArtisanBuild\BuiltForCloud\RotationOverride;
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

/**
 * A declaration OPTED INTO rotation overrides (the dedicated
 * AuthorizesRotationOverrides hook): $allow is its answer, $captured
 * collects every RotationOverride it is consulted with, and $constrained
 * additionally declares the mint ceilings (only `consume` grantable, one
 * hour max lifetime — the ConstrainedMintDeclaration shape).
 */
function bindOverridableDeclaration(?ArrayObject $captured = null, bool $allow = true, bool $constrained = false): void
{
    $captured ??= new ArrayObject;

    $declaration = $constrained
        ? new class($captured) implements AuthorizesRotationOverrides, ConstrainsMintedCredentials, CredentialDeclaration
        {
            public function __construct(private readonly ArrayObject $captured) {}

            public function grantableAbilities(Subject $subject): ?array
            {
                return ['consume'];
            }

            public function maxCredentialLifetimeSeconds(Subject $subject): ?int
            {
                return 3600;
            }

            public function resolveSubject(Request $request): ?Subject
            {
                return null;
            }

            public function authorize(Credential $credential, ?string $ability, Request $request): bool
            {
                return true;
            }

            public function authorizeRotationOverride(?Subject $subject, RotationOverride $override, Request $request): bool
            {
                $this->captured->append($override);

                return true;
            }
        }
    : new class($captured, $allow) implements AuthorizesRotationOverrides, CredentialDeclaration
    {
        public function __construct(
            private readonly ArrayObject $captured,
            private readonly bool $allow,
        ) {}

        public function resolveSubject(Request $request): ?Subject
        {
            return null;
        }

        public function authorize(Credential $credential, ?string $ability, Request $request): bool
        {
            return true;
        }

        public function authorizeRotationOverride(?Subject $subject, RotationOverride $override, Request $request): bool
        {
            $this->captured->append($override);

            return $this->allow;
        }
    };

    app()->bind(CredentialDeclaration::class, fn (): CredentialDeclaration => $declaration);
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

    // The judge's surviving mutation: a defaulted expiry on the
    // replacement would be invisible to the audit/grace assertions —
    // preservation of "no expiry" must be asserted as EXACTLY null.
    expect(Credential::query()->findOrFail($replacementId)->expires_at)->toBeNull();

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

it('denies every override under a declaration that has not opted in — fail closed by default', function (): void {
    // The DEFAULT declaration: no AuthorizesRotationOverrides, and its
    // verb matrix (none) allows routine rotation. The override must still
    // be denied — "separately authorized" means a separate opt-in, not a
    // second yes from the routine gate.
    $source = rotatableSource();

    $refusal = $this->postJson('/bfc/credentials/'.$source->id.'/rotate', [
        'override' => true,
        'abilities' => ['consume', 'admin'],
    ], rotationAdminHeaders())->assertForbidden();

    expect((string) $refusal->json('message'))->toContain('does not authorize this rotation override')
        ->and($source->refresh()->rotated_at)->toBeNull()
        ->and(Credential::query()->count())->toBe(1);

    // The CLI refuses the identical question with the identical message.
    expect(Artisan::call('bfc:credential:rotate', [
        'id' => $source->id,
        '--override' => true,
        '--abilities' => 'consume,admin',
        '--local' => true,
    ]))->toBe(1)
        ->and(trim(Artisan::output()))->toBe((string) $refusal->json('message'));

    // Routine rotation of the very same row remains authorized.
    $this->postJson('/bfc/credentials/'.$source->id.'/rotate', [], rotationAdminHeaders())->assertCreated();
});

it('authorizes a flagged override through the dedicated opt-in hook, hands it the delta, and audits reason plus delta', function (): void {
    $consultations = new ArrayObject;

    bindOverridableDeclaration($consultations);

    $source = rotatableSource();

    $response = $this->postJson('/bfc/credentials/'.$source->id.'/rotate', [
        'override' => true,
        'abilities' => ['consume', 'admin'],
    ], rotationAdminHeaders())->assertCreated();

    $replacement = Credential::query()->findOrFail((string) $response->json('credential.id'));

    expect($replacement->abilities)->toBe(['consume', 'admin']);

    // Exactly one override consultation, carrying the requested delta
    // with its presence flags.
    expect($consultations)->toHaveCount(1);

    /** @var RotationOverride $override */
    $override = $consultations[0];

    expect($override->changesAbilities)->toBeTrue()
        ->and($override->abilities)->toBe(['consume', 'admin'])
        ->and($override->changesExpiry)->toBeFalse();

    $rotated = CredentialAuditEvent::query()
        ->where('credential_id', $source->id)
        ->where('event', LifecycleEventType::Rotated->value)
        ->sole();

    expect($rotated->reason_code)->toBe(AuditReason::Override)
        ->and((string) $rotated->note)->toContain('abilities')
        ->and((string) $rotated->note)->toContain('admin');
});

it('lets an opted-in declaration deny the override while routine rotation stays authorized', function (): void {
    bindOverridableDeclaration(allow: false);

    $source = rotatableSource();

    $refusal = $this->postJson('/bfc/credentials/'.$source->id.'/rotate', [
        'override' => true,
        'abilities' => ['consume', 'admin'],
    ], rotationAdminHeaders())->assertForbidden();

    expect((string) $refusal->json('message'))->toContain('does not authorize this rotation override')
        ->and($source->refresh()->rotated_at)->toBeNull()
        ->and(Credential::query()->count())->toBe(1);

    // The routine path is untouched by the denial.
    $this->postJson('/bfc/credentials/'.$source->id.'/rotate', [], rotationAdminHeaders())->assertCreated();
});

it('refuses an authorized override that exceeds the mint ceilings — an override is never wider than a mint could be', function (): void {
    // Opted into overrides AND declaring mint ceilings: only `consume`
    // grantable, nothing lives longer than an hour.
    bindOverridableDeclaration(constrained: true);

    $source = rotatableSource(['abilities' => ['consume'], 'expires_at' => now()->addMinutes(30)]);

    // Ability past the ceiling: refused with the mint verb's own error.
    $widened = $this->postJson('/bfc/credentials/'.$source->id.'/rotate', [
        'override' => true,
        'abilities' => ['consume', 'admin'],
    ], rotationAdminHeaders())->assertForbidden();

    expect((string) $widened->json('message'))->toContain('does not authorize granting the "admin" ability');

    // Lifetime past the ceiling — including "no expiry", which outlives
    // any ceiling: refused.
    $lengthened = $this->postJson('/bfc/credentials/'.$source->id.'/rotate', [
        'override' => true,
        'expires_at' => now()->addDays(2)->toIso8601String(),
    ], rotationAdminHeaders())->assertForbidden();

    expect((string) $lengthened->json('message'))->toContain('widens past what the declaration authorizes');

    $cleared = $this->postJson('/bfc/credentials/'.$source->id.'/rotate', [
        'override' => true,
        'expires_at' => null,
    ], rotationAdminHeaders())->assertForbidden();

    expect((string) $cleared->json('message'))->toContain('widens past what the declaration authorizes')
        ->and($source->refresh()->rotated_at)->toBeNull()
        ->and(Credential::query()->count())->toBe(1);

    // Within the ceilings the same override applies.
    $this->postJson('/bfc/credentials/'.$source->id.'/rotate', [
        'override' => true,
        'expires_at' => now()->addMinutes(45)->toIso8601String(),
    ], rotationAdminHeaders())->assertCreated();
});

it('overrides a finite expiry to NO expiry with an explicit null, on both transports, audited', function (): void {
    bindOverridableDeclaration();

    $httpSource = rotatableSource(['expires_at' => now()->addDays(30)]);

    $response = $this->postJson('/bfc/credentials/'.$httpSource->id.'/rotate', [
        'override' => true,
        'expires_at' => null,
    ], rotationAdminHeaders())->assertCreated();

    $httpReplacement = Credential::query()->findOrFail((string) $response->json('credential.id'));

    expect($httpReplacement->expires_at)->toBeNull()
        ->and($httpReplacement->abilities)->toBe(['consume']);

    $note = (string) CredentialAuditEvent::query()
        ->where('credential_id', $httpSource->id)
        ->where('event', LifecycleEventType::Rotated->value)
        ->sole()
        ->note;

    expect($note)->toContain('expires_at')
        ->and($note)->toContain('-> null');

    // The CLI spelling of the same override: --clear-expiry.
    $cliSource = rotatableSource(['expires_at' => now()->addDays(30)]);

    expect(Artisan::call('bfc:credential:rotate', [
        'id' => $cliSource->id,
        '--override' => true,
        '--clear-expiry' => true,
        '--local' => true,
    ]))->toBe(0);

    preg_match('/shown once: (\S+)/', Artisan::output(), $matches);

    expect(Credential::query()->where('secret_hash', hash('sha256', $matches[1]))->sole()->expires_at)->toBeNull();
});

it('narrows to NO abilities with an explicit empty list, on both transports, audited', function (): void {
    bindOverridableDeclaration();

    $httpSource = rotatableSource(['abilities' => ['consume', 'read']]);

    $response = $this->postJson('/bfc/credentials/'.$httpSource->id.'/rotate', [
        'override' => true,
        'abilities' => [],
    ], rotationAdminHeaders())->assertCreated();

    $httpReplacement = Credential::query()->findOrFail((string) $response->json('credential.id'));

    // The store's one canonical empty: null. It grants nothing.
    expect($httpReplacement->getAttributes()['abilities'])->toBeNull()
        ->and($httpReplacement->hasAbility('consume'))->toBeFalse()
        ->and($httpReplacement->expires_at?->timestamp)->toBe($httpSource->expires_at?->timestamp);

    $note = (string) CredentialAuditEvent::query()
        ->where('credential_id', $httpSource->id)
        ->where('event', LifecycleEventType::Rotated->value)
        ->sole()
        ->note;

    expect($note)->toContain('abilities ["consume","read"] -> []');

    // The CLI spelling of the same override: --clear-abilities.
    $cliSource = rotatableSource(['abilities' => ['consume', 'read']]);

    expect(Artisan::call('bfc:credential:rotate', [
        'id' => $cliSource->id,
        '--override' => true,
        '--clear-abilities' => true,
        '--local' => true,
    ]))->toBe(0);

    preg_match('/shown once: (\S+)/', Artisan::output(), $matches);

    expect(Credential::query()->where('secret_hash', hash('sha256', $matches[1]))->sole()->getAttributes()['abilities'])->toBeNull();
});

it('still treats absent override fields as preserve — presence, not value, is the signal', function (): void {
    bindOverridableDeclaration();

    $source = rotatableSource(['abilities' => ['consume'], 'expires_at' => now()->addDays(3)]);
    $sourceExpiry = $source->expires_at;

    // Only abilities provided: expiry is preserved, not cleared.
    $response = $this->postJson('/bfc/credentials/'.$source->id.'/rotate', [
        'override' => true,
        'abilities' => ['consume', 'read'],
    ], rotationAdminHeaders())->assertCreated();

    $replacement = Credential::query()->findOrFail((string) $response->json('credential.id'));

    expect($replacement->abilities)->toBe(['consume', 'read'])
        ->and($replacement->expires_at?->timestamp)->toBe($sourceExpiry?->timestamp);
});

// ---------------------------------------------- linear lineage (Fold A)

it('never forks the lineage on re-invocation: a graced row with a live successor completes the cutover, and the successor rotates on', function (): void {
    $source = rotatableSource(['expires_at' => null]);

    $first = $this->postJson('/bfc/credentials/'.$source->id.'/rotate', [], rotationAdminHeaders())
        ->assertCreated();

    $successorId = (string) $first->json('credential.id');

    // Re-invoking the verb on the graced row mints NOTHING — no A→C fork
    // — it performs the retirement-only cutover completion, reporting the
    // standing successor with a `none` delivery.
    $completion = $this->postJson('/bfc/credentials/'.$source->id.'/rotate', [], rotationAdminHeaders())
        ->assertOk();

    expect($completion->json('completed_cutover'))->toBeTrue()
        ->and($completion->json('credential.id'))->toBe($successorId)
        ->and($completion->json('superseded_id'))->toBe($source->id)
        ->and($completion->json('delivery.shape'))->toBe('none')
        ->and($completion->json('delivery.secret'))->toBeNull()
        ->and(Credential::query()->count())->toBe(2);

    // The lineage stayed linear: every rotated event of the source names
    // the ONE successor.
    $sourceRotations = CredentialAuditEvent::query()
        ->where('credential_id', $source->id)
        ->where('event', LifecycleEventType::Rotated->value)
        ->get();

    expect($sourceRotations->pluck('superseded_by_credential_id')->unique()->all())->toBe([$successorId]);

    // The successor is the mintable rotation: the chain stays linear
    // (A → B → C).
    $second = $this->postJson('/bfc/credentials/'.$successorId.'/rotate', [], rotationAdminHeaders())
        ->assertCreated();

    $rotated = CredentialAuditEvent::query()
        ->where('credential_id', $successorId)
        ->where('event', LifecycleEventType::Rotated->value)
        ->sole();

    expect($rotated->superseded_by_credential_id)->toBe((string) $second->json('credential.id'));
});

it('refuses re-rotation of a stamped row whose successor is no longer live, identically on both transports', function (): void {
    $source = rotatableSource(['expires_at' => null]);

    $successorId = (string) $this->postJson('/bfc/credentials/'.$source->id.'/rotate', [], rotationAdminHeaders())
        ->assertCreated()
        ->json('credential.id');

    $this->deleteJson('/bfc/credentials/'.$successorId, [], rotationAdminHeaders())->assertNoContent();

    $refusal = $this->postJson('/bfc/credentials/'.$source->id.'/rotate', [], rotationAdminHeaders())
        ->assertStatus(409);

    $message = (string) $refusal->json('message');

    expect($message)->toContain('already superseded by rotation')
        ->and($message)->toContain($successorId)
        ->and($message)->toContain('no longer live')
        ->and($message)->toContain('Mint a fresh credential');

    expect(Artisan::call('bfc:credential:rotate', ['id' => $source->id, '--local' => true]))->toBe(1)
        ->and(trim(Artisan::output()))->toBe($message)
        ->and(Credential::query()->count())->toBe(2);
});

// ------------------------------------ cutover completion authority (Fix 3)

it('completes a failed cutover under rotate authority alone, with revoke denied, on both transports', function (): void {
    // Rotate allowed, Revoke denied: exactly the declaration that made a
    // failed phase B unrecoverable before the completion path existed.
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
            return $verb !== CredentialVerb::Revoke;
        }
    });

    $cliSource = rotatableSource(['expires_at' => null]);
    $httpSource = rotatableSource(['expires_at' => null]);

    DB::statement("CREATE TRIGGER bfc_fail_cutover_fix3 BEFORE UPDATE OF expires_at ON credentials WHEN NEW.rotated_at IS NOT NULL BEGIN SELECT RAISE(ABORT, 'forced cutover failure'); END");

    foreach ([$cliSource, $httpSource] as $source) {
        $this->postJson('/bfc/credentials/'.$source->id.'/rotate', [], rotationAdminHeaders())->assertStatus(500);
    }

    DB::statement('DROP TRIGGER bfc_fail_cutover_fix3');

    // The revoke verb is denied, so the old rows cannot die that way…
    $this->deleteJson('/bfc/credentials/'.$httpSource->id, [], rotationAdminHeaders())->assertForbidden();

    // …but re-invoking ROTATE completes the cutover on either transport.
    expect(Artisan::call('bfc:credential:rotate', ['id' => $cliSource->id, '--local' => true]))->toBe(0)
        ->and(Artisan::output())->toContain('Cutover completed')
        ->and(Artisan::output())->not->toContain('shown once');

    $completion = $this->postJson('/bfc/credentials/'.$httpSource->id.'/rotate', [], rotationAdminHeaders())
        ->assertOk();

    expect($completion->json('completed_cutover'))->toBeTrue()
        ->and($completion->json('delivery.shape'))->toBe('none');

    foreach ([$cliSource, $httpSource] as $source) {
        $source->refresh();

        expect($source->expires_at)->not->toBeNull()
            ->and($source->expires_at?->lessThanOrEqualTo(now()->addHour()))->toBeTrue();

        expect(CredentialAuditEvent::query()
            ->where('credential_id', $source->id)
            ->where('event', LifecycleEventType::Rotated->value)
            ->where('reason_code', AuditReason::CutoverCompletion->value)
            ->count())->toBe(1);
    }

    // Nothing was minted by either completion: two sources, two successors.
    expect(Credential::query()->count())->toBe(4);
});

it('kills a compromised graced old row immediately via emergency completion', function (): void {
    $source = rotatableSource(['expires_at' => null]);

    $this->postJson('/bfc/credentials/'.$source->id.'/rotate', [], rotationAdminHeaders())->assertCreated();

    // The old secret is compromised mid-grace: emergency completion
    // retires it NOW, minting nothing.
    $this->postJson('/bfc/credentials/'.$source->id.'/rotate', ['emergency' => true], rotationAdminHeaders())
        ->assertOk();

    $source->refresh();

    expect(Credential::query()->active()->pluck('id')->all())->not->toContain($source->id)
        ->and($source->expires_at?->lessThanOrEqualTo(now()))->toBeTrue()
        ->and(Credential::query()->count())->toBe(2);
});

it('is no revoke bypass: an unstamped row cannot be retired without minting its replacement', function (): void {
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
            return $verb !== CredentialVerb::Revoke;
        }
    });

    $source = rotatableSource(['expires_at' => null]);

    // Rotating an unstamped row is ALWAYS the full make-before-break: a
    // live replacement is minted before the old row is retired, so rotate
    // authority can never simply destroy a subject's access.
    $response = $this->postJson('/bfc/credentials/'.$source->id.'/rotate', [], rotationAdminHeaders())
        ->assertCreated();

    expect($response->json('completed_cutover'))->toBeNull()
        ->and(Credential::query()->count())->toBe(2)
        ->and(Credential::query()->active()->pluck('id')->all())->toContain((string) $response->json('credential.id'));
});

it('refuses override options on a completion — nothing is minted for them to change', function (): void {
    bindOverridableDeclaration();

    $source = rotatableSource(['expires_at' => null]);

    $this->postJson('/bfc/credentials/'.$source->id.'/rotate', [], rotationAdminHeaders())->assertCreated();

    $refusal = $this->postJson('/bfc/credentials/'.$source->id.'/rotate', [
        'override' => true,
        'abilities' => ['consume', 'admin'],
    ], rotationAdminHeaders())->assertStatus(422);

    expect((string) $refusal->json('message'))->toContain('override options do not apply')
        ->and(Credential::query()->count())->toBe(2);
});

// -------------------------------------- CLI presence parity (Fix 2)

it('treats an explicitly empty CLI value as present-and-none, byte-identical to the HTTP empty string', function (): void {
    bindOverridableDeclaration();

    $cliSource = rotatableSource(['abilities' => ['consume', 'read']]);
    $httpSource = rotatableSource(['abilities' => ['consume', 'read']]);

    // CLI `--abilities=` and `--expires=`: provided-and-empty.
    expect(Artisan::call('bfc:credential:rotate', [
        'id' => $cliSource->id,
        '--override' => true,
        '--abilities' => '',
        '--expires' => '',
        '--local' => true,
    ]))->toBe(0);

    preg_match('/shown once: (\S+)/', Artisan::output(), $matches);
    $cliReplacement = Credential::query()->where('secret_hash', hash('sha256', $matches[1]))->sole();

    // HTTP "" on the same fields: the identical question.
    $httpResponse = $this->postJson('/bfc/credentials/'.$httpSource->id.'/rotate', [
        'override' => true,
        'abilities' => '',
        'expires_at' => '',
    ], rotationAdminHeaders())->assertCreated();

    $httpReplacement = Credential::query()->findOrFail((string) $httpResponse->json('credential.id'));

    foreach ([$cliReplacement, $httpReplacement] as $replacement) {
        expect($replacement->getAttributes()['abilities'])->toBeNull()
            ->and($replacement->expires_at)->toBeNull();
    }
});

it('refuses a provided-empty value without the override flag identically on both transports', function (): void {
    $cliSource = rotatableSource();
    $httpSource = rotatableSource();

    expect(Artisan::call('bfc:credential:rotate', [
        'id' => $cliSource->id,
        '--abilities' => '',
        '--local' => true,
    ]))->toBe(1);
    $cliMessage = trim(Artisan::output());

    $httpResponse = $this->postJson('/bfc/credentials/'.$httpSource->id.'/rotate', [
        'abilities' => '',
    ], rotationAdminHeaders())->assertStatus(422);

    expect($cliMessage)->toBe((string) $httpResponse->json('message'))
        ->and($cliMessage)->toContain('override')
        ->and($cliSource->refresh()->rotated_at)->toBeNull()
        ->and($httpSource->refresh()->rotated_at)->toBeNull()
        ->and(Credential::query()->count())->toBe(2);
});

// ------------------------------------ non-forgeable provenance (Fix 1)

it('discards a mass-assigned rotated_at: only the rotate verb asserts the sweep-exempting marker', function (): void {
    $forged = Credential::query()->create([
        'kind' => CredentialKind::Bearer,
        'subject_type' => 'external_consumer',
        'subject_ref' => 'forger',
        'abilities' => ['consume'],
        'secret_hash' => hash('sha256', 'forged-secret'),
        'rotated_at' => now(),
    ]);

    expect($forged->refresh()->rotated_at)->toBeNull();
});

// ------------------------------------------ grace-boundary precision (Fold B)

it('resolves the graced row until the exact grace end and not after it', function (): void {
    $frozen = now()->startOfSecond();
    $this->travelTo($frozen);

    $source = rotatableSource(['expires_at' => null]);

    $this->postJson('/bfc/credentials/'.$source->id.'/rotate', [], rotationAdminHeaders())->assertCreated();

    $graceEnd = $frozen->copy()->addHour();

    expect($source->refresh()->expires_at?->timestamp)->toBe($graceEnd->timestamp);

    $resolves = fn (): bool => Credential::query()->active()->whereKey($source->id)->exists();

    // One second before grace end: still resolvable.
    $this->travelTo($graceEnd->copy()->subSecond());
    expect($resolves())->toBeTrue();

    // At the boundary itself the row is dead: resolvability requires
    // expires_at strictly in the future.
    $this->travelTo($graceEnd);
    expect($resolves())->toBeFalse();
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
