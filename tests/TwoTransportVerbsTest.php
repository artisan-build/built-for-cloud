<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\AuditActorType;
use ArtisanBuild\BuiltForCloud\Contracts\AuthorizesCredentialVerbs;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialOutboxEntry;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\CredentialVerb;
use ArtisanBuild\BuiltForCloud\DefaultCredentialDeclaration;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\OnboardingToken;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\Testing\DetectsSecretLeaks;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\ConstrainedMintDeclaration;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\ReelLikeDeclaration;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Process;
use Illuminate\Testing\TestResponse;
use Symfony\Component\HttpFoundation\Response;

uses(RefreshDatabase::class, DetectsSecretLeaks::class);

/**
 * @return array{Authorization: string}
 */
function transportAdminHeaders(string $name = 'transport-admin'): array
{
    return ['Authorization' => 'Bearer '.auditAdminToken($name.'-'.bin2hex(random_bytes(4)))];
}

function bindDenyingMatrix(CredentialVerb $denied): void
{
    app()->bind(CredentialDeclaration::class, static fn (): CredentialDeclaration => new class($denied) implements AuthorizesCredentialVerbs, CredentialDeclaration
    {
        public function __construct(private readonly CredentialVerb $denied) {}

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
            return $verb !== $this->denied;
        }
    });
}

/**
 * @return list<string>
 */
function eventsFor(string $credentialId): array
{
    return CredentialAuditEvent::query()
        ->where('credential_id', $credentialId)
        ->orderBy('occurred_at')
        ->pluck('event')
        ->map(fn ($event): string => $event->value)
        ->values()
        ->all();
}

// ---------------------------------------------------------------- mint: CLI

it('mints a bearer credential via the CLI with --local, revealing the secret exactly once and leaking it nowhere', function (): void {
    Process::fake();

    $output = $this->assertNoSecretLeakageOfMinted(
        function (): string {
            expect(Artisan::call('bfc:credential:mint', [
                'subject-type' => 'external_consumer',
                'subject-ref' => 'acme',
                '--name' => 'ci',
                '--abilities' => 'consume,read',
                '--local' => true,
            ]))->toBe(0);

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

    $credential = Credential::query()->where('subject_ref', 'acme')->sole();

    expect($credential->kind)->toBe(CredentialKind::Bearer)
        ->and($credential->name)->toBe('ci')
        ->and($credential->abilities)->toBe(['consume', 'read'])
        ->and($credential->expires_at)->toBeNull()
        ->and($credential->secret_hash)->toBe(hash('sha256', $secret))
        ->and($credential->status)->toBe(CredentialStatus::Active);

    // AC8: `issued` emitted through the recorder — audit row AND outbox
    // row, ids only, with the CLI's honest actor.
    expect(eventsFor($credential->id))->toBe([LifecycleEventType::Issued->value]);

    $event = CredentialAuditEvent::query()->where('credential_id', $credential->id)->sole();

    expect($event->actor_type)->toBe(AuditActorType::CliOperator)
        ->and(CredentialOutboxEntry::query()->where('audit_event_id', $event->id)->exists())->toBeTrue();

    // Zero Cloud dependency: nothing shelled out.
    Process::assertNothingRan();
});

it('refuses to run the unified verbs without --local, pointing at the HTTP contract', function (): void {
    Process::fake();

    expect(Artisan::call('bfc:credential:mint', [
        'subject-type' => 'external_consumer',
        'subject-ref' => 'acme',
    ]))->toBe(1)
        ->and(Artisan::output())->toContain('--local')
        ->and(Credential::query()->count())->toBe(0);

    expect(Artisan::call('bfc:credential:list'))->toBe(1);
    expect(Artisan::call('bfc:credential:revoke', ['id' => 'nope']))->toBe(1);

    Process::assertNothingRan();
});

it('mints a basic credential via the CLI, delivering the auth.json pair', function (): void {
    expect(Artisan::call('bfc:credential:mint', [
        'subject-type' => 'external_consumer',
        'subject-ref' => 'crate-org',
        '--kind' => 'basic',
        '--local' => true,
    ]))->toBe(0);

    $output = Artisan::output();
    $credential = Credential::query()->where('subject_ref', 'crate-org')->sole();

    preg_match('/shown once: (\S+)/', $output, $matches);

    expect($output)->toContain('auth.json username: '.$credential->id)
        ->and($credential->kind)->toBe(CredentialKind::Basic)
        ->and($credential->secret_hash)->toBe(hash('sha256', $matches[1]));
});

it('mints an asymmetric enrollment via the CLI: a pending row and a linked claim code, never key material', function (): void {
    expect(Artisan::call('bfc:credential:mint', [
        'subject-type' => 'application',
        'subject-ref' => 'reel-app-7',
        '--kind' => 'asymmetric',
        '--code-ttl' => '900',
        '--local' => true,
    ]))->toBe(0);

    $output = Artisan::output();
    $credential = Credential::query()->where('subject_ref', 'reel-app-7')->sole();

    expect($credential->status)->toBe(CredentialStatus::Pending)
        ->and($credential->kind)->toBe(CredentialKind::Asymmetric)
        ->and($credential->secret_hash)->toBeNull()
        ->and($credential->public_key)->toBeNull();

    preg_match('/Enrollment code - shown once: (\S+)/', $output, $matches);
    $code = OnboardingToken::query()->where('durable_token_id', $credential->id)->sole();

    expect($code->token_hash)->toBe(hash('sha256', $matches[1]))
        ->and($code->scope)->toBe(Scope::Onboard->value)
        ->and($code->consumed_at)->toBeNull()
        ->and($code->expires_at->timestamp)->toBeGreaterThan(now()->addSeconds(850)->timestamp)
        ->and($code->expires_at->timestamp)->toBeLessThanOrEqual(now()->addSeconds(900)->timestamp);

    $event = CredentialAuditEvent::query()->where('credential_id', $credential->id)->sole();

    expect($event->event)->toBe(LifecycleEventType::Issued)
        ->and($event->code_id)->toBe($code->id)
        ->and($event->code_ttl_seconds)->toBe(900);
});

it('requires a bounded code ttl for the asymmetric kind on both transports, with the same error', function (): void {
    expect(Artisan::call('bfc:credential:mint', [
        'subject-type' => 'application',
        'subject-ref' => 'reel-app-8',
        '--kind' => 'asymmetric',
        '--local' => true,
    ]))->toBe(1);

    $cliMessage = trim(Artisan::output());

    $response = $this->postJson('/bfc/credentials', [
        'subject_type' => 'application',
        'subject_ref' => 'reel-app-8',
        'kind' => 'asymmetric',
        'code_ttl_seconds' => 30,
    ], transportAdminHeaders())->assertUnprocessable();

    // The ONE bounds rule, enforced in the action: the same message on
    // both transports.
    expect($cliMessage)->toContain((string) $response->json('message'))
        ->and(Credential::query()->count())->toBe(0);
});

it('rejects a non-integer code ttl identically on both transports — 60junk is junk, never 60', function (): void {
    expect(Artisan::call('bfc:credential:mint', [
        'subject-type' => 'application',
        'subject-ref' => 'reel-junk',
        '--kind' => 'asymmetric',
        '--code-ttl' => '60junk',
        '--local' => true,
    ]))->toBe(1);

    $cliMessage = trim(Artisan::output());

    $response = $this->postJson('/bfc/credentials', [
        'subject_type' => 'application',
        'subject_ref' => 'reel-junk',
        'kind' => 'asymmetric',
        'code_ttl_seconds' => '60junk',
    ], transportAdminHeaders())->assertUnprocessable();

    $httpMessage = (string) $response->json('message');

    expect($httpMessage)->toContain('whole number')
        ->and($cliMessage)->toContain($httpMessage)
        // Nothing was minted from the junk — neither a row nor a code.
        ->and(Credential::query()->count())->toBe(0)
        ->and(OnboardingToken::query()->count())->toBe(0);
});

it('converges a negative code ttl onto the same bounds error on both transports', function (): void {
    expect(Artisan::call('bfc:credential:mint', [
        'subject-type' => 'application',
        'subject-ref' => 'reel-negative',
        '--kind' => 'asymmetric',
        '--code-ttl' => '-1',
        '--local' => true,
    ]))->toBe(1);

    $cliMessage = trim(Artisan::output());

    $response = $this->postJson('/bfc/credentials', [
        'subject_type' => 'application',
        'subject_ref' => 'reel-negative',
        'kind' => 'asymmetric',
        'code_ttl_seconds' => -1,
    ], transportAdminHeaders())->assertUnprocessable();

    // The CLI's "-1" parses as the integer the HTTP leg sends, so BOTH
    // hit the one bounds error — not a divergent "not an integer".
    expect($cliMessage)->toBe((string) $response->json('message'))
        ->and($cliMessage)->toContain('between 60 and 604800')
        ->and(Credential::query()->count())->toBe(0);
});

it('bounds the abilities count identically on both transports', function (): void {
    $abilities = array_map(static fn (int $i): string => 'ability-'.$i, range(1, 33));

    expect(Artisan::call('bfc:credential:mint', [
        'subject-type' => 'external_consumer',
        'subject-ref' => 'greedy',
        '--abilities' => implode(',', $abilities),
        '--local' => true,
    ]))->toBe(1);

    $cliMessage = trim(Artisan::output());

    $response = $this->postJson('/bfc/credentials', [
        'subject_type' => 'external_consumer',
        'subject_ref' => 'greedy',
        'abilities' => $abilities,
    ], transportAdminHeaders())->assertUnprocessable();

    expect($cliMessage)->toBe((string) $response->json('message'))
        ->and($cliMessage)->toContain('at most 32 abilities')
        ->and(Credential::query()->count())->toBe(0);
});

it('bounds the ability entry length identically on both transports', function (): void {
    $tooLong = str_repeat('a', 129);

    expect(Artisan::call('bfc:credential:mint', [
        'subject-type' => 'external_consumer',
        'subject-ref' => 'verbose',
        '--abilities' => $tooLong,
        '--local' => true,
    ]))->toBe(1);

    $cliMessage = trim(Artisan::output());

    $response = $this->postJson('/bfc/credentials', [
        'subject_type' => 'external_consumer',
        'subject_ref' => 'verbose',
        'abilities' => [$tooLong],
    ], transportAdminHeaders())->assertUnprocessable();

    expect($cliMessage)->toBe((string) $response->json('message'))
        ->and($cliMessage)->toContain('at most 128 characters')
        ->and(Credential::query()->count())->toBe(0);
});

it('normalizes an empty abilities list to null identically on both transports', function (): void {
    // HTTP: an explicit empty array.
    $this->postJson('/bfc/credentials', [
        'subject_type' => 'external_consumer',
        'subject_ref' => 'empty-http',
        'abilities' => [],
    ], transportAdminHeaders())->assertCreated()
        ->assertJsonPath('credential.abilities', null);

    // CLI: a comma-and-whitespace string that normalizes to nothing.
    expect(Artisan::call('bfc:credential:mint', [
        'subject-type' => 'external_consumer',
        'subject-ref' => 'empty-cli',
        '--abilities' => ' , ,',
        '--local' => true,
    ]))->toBe(0);

    // One canonical shape at rest and in every listing row: null.
    expect(Credential::query()->where('subject_ref', 'empty-http')->sole()->abilities)->toBeNull()
        ->and(Credential::query()->where('subject_ref', 'empty-cli')->sole()->abilities)->toBeNull();

    Artisan::call('bfc:credential:list', ['--json' => true, '--local' => true]);

    foreach (json_decode(trim(Artisan::output()), true) as $row) {
        expect($row['abilities'])->toBeNull();
    }
});

it('refuses the hmac kind identically on both transports', function (): void {
    expect(Artisan::call('bfc:credential:mint', [
        'subject-type' => 'application',
        'subject-ref' => 'postmaster',
        '--kind' => 'hmac',
        '--local' => true,
    ]))->toBe(1)
        ->and(Artisan::output())->toContain('not mintable');

    $this->postJson('/bfc/credentials', [
        'subject_type' => 'application',
        'subject_ref' => 'postmaster',
        'kind' => 'hmac',
    ], transportAdminHeaders())
        ->assertForbidden()
        ->assertJsonPath('message', fn (string $message): bool => str_contains($message, 'not mintable'));

    expect(Credential::query()->count())->toBe(0);
});

// --------------------------------------------------------------- mint: HTTP

it('mints a bearer credential via HTTP, revealing the secret once in the response and leaking it nowhere', function (): void {
    $headers = transportAdminHeaders();

    /** @var TestResponse<Response> $response */
    $response = $this->assertNoSecretLeakageOfMinted(
        fn (): TestResponse => $this->postJson('/bfc/credentials', [
            'subject_type' => 'external_consumer',
            'subject_ref' => 'acme-http',
            'name' => 'ci',
            'abilities' => ['consume'],
        ], $headers),
        fn (TestResponse $response): string => (string) $response->json('delivery.secret'),
    );

    $response->assertCreated()
        ->assertJsonPath('delivery.shape', 'bearer')
        ->assertJsonPath('credential.kind', 'bearer')
        ->assertJsonPath('credential.subject_type', 'external_consumer')
        ->assertJsonPath('credential.subject_ref', 'acme-http')
        ->assertJsonPath('credential.status', 'active')
        ->assertJsonPath('credential.unsupported', []);

    $secret = (string) $response->json('delivery.secret');
    $credential = Credential::query()->where('subject_ref', 'acme-http')->sole();

    $this->assertRevealsSecretExactlyOnce((string) $response->getContent(), $secret);

    expect($credential->secret_hash)->toBe(hash('sha256', $secret))
        ->and(eventsFor($credential->id))->toBe([LifecycleEventType::Issued->value]);

    // The HTTP transport's honest actor: the admin token the gate
    // authenticated.
    $event = CredentialAuditEvent::query()->where('credential_id', $credential->id)->sole();

    expect($event->actor_type)->toBe(AuditActorType::AdminToken)
        ->and(ApiToken::query()->whereKey($event->actor_ref)->exists())->toBeTrue();
});

it('mints a basic credential via HTTP with the auth.json pair in the delivery', function (): void {
    $response = $this->postJson('/bfc/credentials', [
        'subject_type' => 'external_consumer',
        'subject_ref' => 'crate-http',
        'kind' => 'basic',
    ], transportAdminHeaders())->assertCreated();

    $credential = Credential::query()->where('subject_ref', 'crate-http')->sole();

    expect($response->json('delivery.shape'))->toBe('basic_auth')
        ->and($response->json('delivery.username'))->toBe($credential->id)
        ->and($credential->secret_hash)->toBe(hash('sha256', (string) $response->json('delivery.password')));
});

it('mints an asymmetric enrollment via HTTP delivering the enrollment code', function (): void {
    $response = $this->postJson('/bfc/credentials', [
        'subject_type' => 'application',
        'subject_ref' => 'reel-http',
        'kind' => 'asymmetric',
        'code_ttl_seconds' => 900,
    ], transportAdminHeaders())->assertCreated();

    $credential = Credential::query()->where('subject_ref', 'reel-http')->sole();
    $code = OnboardingToken::query()->where('durable_token_id', $credential->id)->sole();

    expect($response->json('delivery.shape'))->toBe('enrollment_code')
        ->and($response->json('credential.status'))->toBe('pending')
        ->and($code->token_hash)->toBe(hash('sha256', (string) $response->json('delivery.enrollment_code')));
});

it('gates the HTTP verbs behind the admin token', function (): void {
    $this->getJson('/bfc/credentials')->assertUnauthorized();
    $this->postJson('/bfc/credentials', [])->assertUnauthorized();
    $this->deleteJson('/bfc/credentials/some-id')->assertUnauthorized();

    $consume = auditAdminToken('not-admin-'.bin2hex(random_bytes(4)));
    ApiToken::query()->where('token_hash', hash('sha256', $consume))->update(['abilities' => [Scope::Consume->value]]);

    $this->getJson('/bfc/credentials', ['Authorization' => 'Bearer '.$consume])->assertForbidden();
});

// --------------------------------------------- widening + matrix refusals

it('refuses ability widening past the declared ceiling on both transports', function (): void {
    app()->bind(CredentialDeclaration::class, ConstrainedMintDeclaration::class);

    expect(Artisan::call('bfc:credential:mint', [
        'subject-type' => 'external_consumer',
        'subject-ref' => 'ceiling',
        '--abilities' => 'consume,admin',
        '--expires' => now()->addMinutes(30)->toIso8601String(),
        '--local' => true,
    ]))->toBe(1)
        ->and(Artisan::output())->toContain('"admin"');

    $this->postJson('/bfc/credentials', [
        'subject_type' => 'external_consumer',
        'subject_ref' => 'ceiling',
        'abilities' => ['consume', 'admin'],
        'expires_at' => now()->addMinutes(30)->toIso8601String(),
    ], transportAdminHeaders())->assertForbidden();

    expect(Credential::query()->count())->toBe(0);
});

it('refuses lifetime widening — a later expiry OR no expiry at all — past the declared ceiling on both transports', function (): void {
    app()->bind(CredentialDeclaration::class, ConstrainedMintDeclaration::class);

    // Too long.
    expect(Artisan::call('bfc:credential:mint', [
        'subject-type' => 'external_consumer',
        'subject-ref' => 'long-lived',
        '--expires' => now()->addDay()->toIso8601String(),
        '--local' => true,
    ]))->toBe(1);

    // No expiry outlives any ceiling.
    expect(Artisan::call('bfc:credential:mint', [
        'subject-type' => 'external_consumer',
        'subject-ref' => 'immortal',
        '--local' => true,
    ]))->toBe(1)
        ->and(Artisan::output())->toContain('never substitutes');

    $this->postJson('/bfc/credentials', [
        'subject_type' => 'external_consumer',
        'subject_ref' => 'immortal',
    ], transportAdminHeaders())->assertForbidden();

    expect(Credential::query()->count())->toBe(0);

    // Within the ceiling: minted.
    expect(Artisan::call('bfc:credential:mint', [
        'subject-type' => 'external_consumer',
        'subject-ref' => 'bounded',
        '--abilities' => 'consume',
        '--expires' => now()->addMinutes(30)->toIso8601String(),
        '--local' => true,
    ]))->toBe(0)
        ->and(Credential::query()->where('subject_ref', 'bounded')->exists())->toBeTrue();
});

it('refuses the mint on both transports when the declaration denies the issue verb', function (): void {
    bindDenyingMatrix(CredentialVerb::Issue);

    expect(Artisan::call('bfc:credential:mint', [
        'subject-type' => 'external_consumer',
        'subject-ref' => 'denied',
        '--local' => true,
    ]))->toBe(1)
        ->and(Artisan::output())->toContain('denies the issue verb');

    $this->postJson('/bfc/credentials', [
        'subject_type' => 'external_consumer',
        'subject_ref' => 'denied',
    ], transportAdminHeaders())->assertForbidden();

    expect(Credential::query()->count())->toBe(0);
});

// ------------------------------------------------- declared-unsupported (AC4)

it('round-trips the declared-unsupported discrimination through both transports', function (): void {
    // A row minted under the default declaration first: its nulls mean
    // "absent but supported".
    Credential::factory()->create(['subject_ref' => 'plain', 'name' => null, 'abilities' => null]);

    app()->bind(CredentialDeclaration::class, ReelLikeDeclaration::class);

    expect(Artisan::call('bfc:credential:list', ['--json' => true, '--local' => true]))->toBe(0);

    $cliRows = json_decode(trim(Artisan::output()), true);
    $httpRows = $this->getJson('/bfc/credentials', transportAdminHeaders())->assertOk()->json();

    expect($cliRows)->toBe($httpRows);

    $row = $cliRows[0];

    // Null AND listed: unknowable here — a consumer can distinguish this
    // from the same nulls under a declaration that supports the fields.
    expect($row['name'])->toBeNull()
        ->and($row['abilities'])->toBeNull()
        ->and($row['unsupported'])->toBe(['name', 'abilities', 'last_used_at', 'expires_at']);

    // The same rows under the default declaration: null but NOT listed.
    app()->bind(CredentialDeclaration::class, DefaultCredentialDeclaration::class);

    $supportedRows = $this->getJson('/bfc/credentials', transportAdminHeaders())->assertOk()->json();

    expect($supportedRows[0]['name'])->toBeNull()
        ->and($supportedRows[0]['unsupported'])->toBe([]);
});

it('refuses a mint that sets a declared-unsupported field, on both transports', function (): void {
    app()->bind(CredentialDeclaration::class, ReelLikeDeclaration::class);

    expect(Artisan::call('bfc:credential:mint', [
        'subject-type' => 'application',
        'subject-ref' => 'reel-app',
        '--name' => 'not-allowed',
        '--local' => true,
    ]))->toBe(1)
        ->and(Artisan::output())->toContain('unsupported');

    $this->postJson('/bfc/credentials', [
        'subject_type' => 'application',
        'subject_ref' => 'reel-app',
        'abilities' => ['consume'],
    ], transportAdminHeaders())->assertForbidden();

    expect(Credential::query()->count())->toBe(0);
});

// ------------------------------------------------------------------- list

it('filters the listing per row through the verb matrix on both transports', function (): void {
    Credential::factory()->create(['subject_ref' => 'visible']);
    Credential::factory()->create(['subject_ref' => 'hidden']);

    app()->bind(CredentialDeclaration::class, static fn (): CredentialDeclaration => new class implements AuthorizesCredentialVerbs, CredentialDeclaration
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
            return $verb !== CredentialVerb::ListMetadata || $subject?->ref !== 'hidden';
        }
    });

    expect(Artisan::call('bfc:credential:list', ['--json' => true, '--local' => true]))->toBe(0);

    $cliRows = json_decode(trim(Artisan::output()), true);
    $httpRows = $this->getJson('/bfc/credentials', transportAdminHeaders())->assertOk()->json();

    expect($cliRows)->toBe($httpRows)
        ->and(array_column($cliRows, 'subject_ref'))->toBe(['visible']);
});

it('never serializes a hash or secret column in the listing', function (): void {
    Credential::factory()->create();

    $response = $this->getJson('/bfc/credentials', transportAdminHeaders())->assertOk();

    expect((string) $response->getContent())->not->toContain('secret_hash')
        ->and(array_keys($response->json()[0]))->toBe([
            'id', 'kind', 'subject_type', 'subject_ref', 'name', 'abilities', 'status',
            'created_at', 'last_used_at', 'expires_at', 'revoked_at',
            'presentation_cadence_seconds', 'unsupported',
        ]);
});

// ----------------------------------------------------------------- revoke

it('revokes by id via both transports with identical outcomes', function (): void {
    $cliTarget = Credential::factory()->create(['subject_ref' => 'cli-kill']);
    $httpTarget = Credential::factory()->create(['subject_ref' => 'http-kill']);

    Process::fake();

    expect(Artisan::call('bfc:credential:revoke', ['id' => $cliTarget->id, '--local' => true]))->toBe(0);
    Process::assertNothingRan();

    $this->deleteJson('/bfc/credentials/'.$httpTarget->id, [], transportAdminHeaders())->assertNoContent();

    foreach ([$cliTarget, $httpTarget] as $target) {
        expect($target->refresh()->revoked_at)->not->toBeNull()
            ->and(eventsFor($target->id))->toBe([LifecycleEventType::Revoked->value]);
    }
});

it('is idempotent on already-dead rows and 404s unknown ids, on both transports', function (): void {
    $dead = Credential::factory()->revoked()->create();

    expect(Artisan::call('bfc:credential:revoke', ['id' => $dead->id, '--local' => true]))->toBe(0)
        ->and(Artisan::output())->toContain('already dead');

    $this->deleteJson('/bfc/credentials/'.$dead->id, [], transportAdminHeaders())->assertNoContent();

    // One death, zero NEW audit events (the factory row died without one).
    expect(eventsFor($dead->id))->toBe([]);

    expect(Artisan::call('bfc:credential:revoke', ['id' => 'ffffffff-0000-0000-0000-000000000000', '--local' => true]))->toBe(1);
    $this->deleteJson('/bfc/credentials/ffffffff-0000-0000-0000-000000000000', [], transportAdminHeaders())->assertNotFound();
});

it('refuses the revoke on both transports when the declaration denies it', function (): void {
    $target = Credential::factory()->create();

    bindDenyingMatrix(CredentialVerb::Revoke);

    expect(Artisan::call('bfc:credential:revoke', ['id' => $target->id, '--local' => true]))->toBe(1);

    $this->deleteJson('/bfc/credentials/'.$target->id, [], transportAdminHeaders())->assertForbidden();

    expect($target->refresh()->revoked_at)->toBeNull();
});

it('revoking a pending enrollment consumes its outstanding claim code', function (): void {
    Artisan::call('bfc:credential:mint', [
        'subject-type' => 'application',
        'subject-ref' => 'reel-pending',
        '--kind' => 'asymmetric',
        '--code-ttl' => '900',
        '--local' => true,
    ]);

    $credential = Credential::query()->where('subject_ref', 'reel-pending')->sole();

    $this->deleteJson('/bfc/credentials/'.$credential->id, [], transportAdminHeaders())->assertNoContent();

    expect($credential->refresh()->revoked_at)->not->toBeNull()
        ->and(OnboardingToken::query()->where('durable_token_id', $credential->id)->sole()->consumed_at)->not->toBeNull();
});
