<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\AuditActorType;
use ArtisanBuild\BuiltForCloud\BuiltForCloud;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\DefaultCredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ConsoleVitals;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\ContractAssertions;
use ArtisanBuild\BuiltForCloud\Testing\MintedTestCredential;
use ArtisanBuild\BuiltForCloud\Testing\WithCredentials;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\HeadlineDeclaration;
use ArtisanBuild\BuiltForCloud\Vitals\HeadlineStat;
use ArtisanBuild\BuiltForCloud\Vitals\HeadlineUnit;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\RateLimiter;

uses(RefreshDatabase::class, WithCredentials::class, ContractAssertions::class);

/**
 * Console PRD §4.6 (D9 / D15 / D16) — the metadata-class vitals endpoint
 * the fleet dashboard reads.
 *
 * The §7 acceptance line this file drives: "every dashboard request
 * carries ONLY the `metadata:read` operator token (asserted by a test
 * that fails on any other credential)", plus D9's honest degradation and
 * D15's bounded shape.
 */
beforeEach(function (): void {
    // The gate authenticates through the `bfc` guard; a consuming app
    // registers it, so the test harness does too.
    config([
        'auth.guards.bfc' => ['driver' => 'bfc', 'provider' => 'users'],
        'queue.default' => 'database',
        'queue.connections.database' => [
            'driver' => 'database',
            'table' => 'jobs',
            'queue' => 'default',
            'retry_after' => 90,
        ],
        'queue.failed' => ['driver' => 'database-uuids', 'database' => null, 'table' => 'failed_jobs'],
    ]);

    HeadlineDeclaration::reset();
});

/**
 * A credential holding exactly the dashboard's ability and nothing else.
 */
function vitalsReader(): MintedTestCredential
{
    return test()->mintCredential([
        'subject_type' => SubjectType::Operator,
        'subject_ref' => 'console-'.bin2hex(random_bytes(4)),
        'abilities' => [OperatorAbility::MetadataRead->value],
    ]);
}

/**
 * Bind the headline-declaring fixture as the app's contract declaration.
 *
 * @param  list<string>  $labels
 */
function vitalsDeclareHeadline(array $labels, ?HeadlineStat $stat): void
{
    HeadlineDeclaration::$labels = $labels;
    HeadlineDeclaration::$stat = $stat;

    app()->bind(CredentialDeclaration::class, HeadlineDeclaration::class);
}

// ---------------------------------------------------------------- AC1 --

it('serves the vitals payload to a credential carrying metadata:read', function (): void {
    config([
        'built-for-cloud.vitals.app_version' => '1.4.2',
        'built-for-cloud.vitals.deployed_at' => now()->subHour()->toAtomString(),
    ]);

    $reader = vitalsReader();

    $response = $this->getJson('/bfc/console/vitals', ['Authorization' => $reader->bearerHeader()])
        ->assertOk()
        ->assertJsonStructure([
            'version', 'api_version', 'bfc_version', 'app_version', 'health',
            'deployed_at', 'deploy_age_seconds',
            'queue' => ['pending', 'reserved', 'failed', 'oldest_pending_age_seconds'],
            'headline',
        ]);

    expect($response->json('version'))->toBe(1)
        ->and($response->json('api_version'))->toBe(BuiltForCloud::API_VERSION)
        ->and($response->json('bfc_version'))->toBe(BuiltForCloud::VERSION)
        ->and($response->json('app_version'))->toBe('1.4.2')
        ->and($response->json('health'))->toBe('ok')
        ->and($response->json('deploy_age_seconds'))->toBeGreaterThanOrEqual(3600)
        ->and($response->json('queue.pending'))->toBe(0)
        ->and($response->json('queue.reserved'))->toBe(0)
        ->and($response->json('queue.failed'))->toBe(0)
        ->and($response->json('queue.oldest_pending_age_seconds'))->toBeNull()
        // No vocabulary declared, so no headline — never a fabricated one.
        ->and($response->json('headline'))->toBeNull()
        // `product` is the one string /bfc/meta carries that no
        // metadata-classified endpoint may: it is operator-authored.
        ->and($response->json())->not->toHaveKey('product');
});

it('reports the real queue backlog, oldest pending job included', function (): void {
    DB::table('jobs')->insert([
        ['queue' => 'default', 'payload' => '{}', 'attempts' => 0, 'reserved_at' => null, 'available_at' => now()->getTimestamp(), 'created_at' => now()->subSeconds(90)->getTimestamp()],
        ['queue' => 'default', 'payload' => '{}', 'attempts' => 0, 'reserved_at' => null, 'available_at' => now()->getTimestamp(), 'created_at' => now()->subSeconds(30)->getTimestamp()],
        ['queue' => 'default', 'payload' => '{}', 'attempts' => 1, 'reserved_at' => now()->getTimestamp(), 'available_at' => now()->getTimestamp(), 'created_at' => now()->subSeconds(10)->getTimestamp()],
    ]);

    $response = $this->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()])
        ->assertOk();

    expect($response->json('queue.pending'))->toBe(2)
        ->and($response->json('queue.reserved'))->toBe(1)
        ->and($response->json('queue.oldest_pending_age_seconds'))->toBeGreaterThanOrEqual(90)
        ->and($response->json('health'))->toBe('ok');
});

// ---------------------------------------------------------------- AC2 --

/**
 * D16's core prohibition, and the §7 acceptance row: the dashboard read
 * is reachable by `metadata:read` and by NOTHING else — the break-glass
 * `credential:admin` and a legacy admin token explicitly included.
 */
it('refuses every credential but metadata:read, break-glass and legacy admin token included', function (): void {
    // The positive control first, so a blanket refusal cannot pass this
    // test by refusing everything.
    $this->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()])->assertOk();

    // The ownership/admin credential. This is the one D16 names, and the
    // reason the route is not mounted behind the operator gate: that gate
    // grants `credential:admin` whatever ability a route asks for.
    $breakGlass = $this->mintCredential([
        'subject_type' => SubjectType::Operator,
        'subject_ref' => 'control-plane',
        'abilities' => [OperatorAbility::ADMIN],
    ]);

    $this->getJson('/bfc/console/vitals', ['Authorization' => $breakGlass->bearerHeader()])->assertForbidden();

    // A legacy admin `api_tokens` row — admin-equivalent on every
    // operator verb route, and not a credential here at all.
    $legacy = 'legacy-admin-'.bin2hex(random_bytes(16));

    ApiToken::query()->create([
        'name' => 'owner',
        'token_hash' => hash('sha256', $legacy),
        'abilities' => [Scope::Admin->value],
    ]);

    $this->getJson('/bfc/console/vitals', ['Authorization' => 'Bearer '.$legacy])->assertUnauthorized();

    // Every other name in the vocabulary, one at a time, plus the
    // no-abilities and empty-abilities shapes.
    $others = array_values(array_filter(
        OperatorAbility::cases(),
        static fn (OperatorAbility $ability): bool => $ability !== OperatorAbility::MetadataRead,
    ));

    foreach ($others as $ability) {
        $credential = $this->mintCredential([
            'subject_type' => SubjectType::Operator,
            'subject_ref' => 'op-'.bin2hex(random_bytes(4)),
            'abilities' => [$ability->value],
        ]);

        $this->getJson('/bfc/console/vitals', ['Authorization' => $credential->bearerHeader()])
            ->assertForbidden();
    }

    foreach ([null, []] as $empty) {
        $bare = $this->mintCredential([
            'subject_type' => SubjectType::Operator,
            'subject_ref' => 'bare-'.bin2hex(random_bytes(4)),
            'abilities' => $empty,
        ]);

        $this->getJson('/bfc/console/vitals', ['Authorization' => $bare->bearerHeader()])->assertForbidden();
    }

    // And the deprecated env pseudo-credential, which the unified-store
    // guard has no code path to.
    config(['built-for-cloud.fallback_token' => 'fallback-secret-bytes']);

    $this->getJson('/bfc/console/vitals', ['Authorization' => 'Bearer fallback-secret-bytes'])
        ->assertUnauthorized();
});

it('audits a denied dashboard read with the acting credential', function (): void {
    $breakGlass = $this->mintCredential([
        'subject_type' => SubjectType::Operator,
        'subject_ref' => 'control-plane',
        'abilities' => [OperatorAbility::ADMIN],
    ]);

    $this->getJson('/bfc/console/vitals', ['Authorization' => $breakGlass->bearerHeader()])->assertForbidden();

    $denied = CredentialAuditEvent::query()
        ->where('event', LifecycleEventType::DeniedAction->value)
        ->get();

    expect($denied)->toHaveCount(1)
        ->and($denied[0]->actor_type)->toBe(AuditActorType::OperatorIntegration)
        ->and($denied[0]->actor_ref)->toBe($breakGlass->credential->id)
        ->and((string) $denied[0]->note)->toContain(OperatorAbility::MetadataRead->value)
        ->and((string) $denied[0]->note)->not->toContain($breakGlass->plaintext());
});

// ---------------------------------------------------------------- AC3 --

it('refuses no credential, an unknown one and an expired or revoked one indistinguishably', function (): void {
    $expired = $this->mintCredential([
        'subject_type' => SubjectType::Operator,
        'subject_ref' => 'expired',
        'abilities' => [OperatorAbility::MetadataRead->value],
        'expires_at' => now()->subMinute(),
    ]);

    $revoked = $this->mintCredential([
        'subject_type' => SubjectType::Operator,
        'subject_ref' => 'revoked',
        'abilities' => [OperatorAbility::MetadataRead->value],
        'revoked_at' => now(),
    ]);

    $answers = [
        'none' => $this->getJson('/bfc/console/vitals'),
        'unknown' => $this->getJson('/bfc/console/vitals', ['Authorization' => 'Bearer unknown-'.bin2hex(random_bytes(16))]),
        'expired' => $this->getJson('/bfc/console/vitals', ['Authorization' => $expired->bearerHeader()]),
        'revoked' => $this->getJson('/bfc/console/vitals', ['Authorization' => $revoked->bearerHeader()]),
    ];

    foreach ($answers as $name => $answer) {
        expect($answer->getStatusCode())->toBe(401, $name)
            ->and($answer->getContent())->toBe($answers['none']->getContent(), $name);
    }

    // Nothing served: not one vitals read was audited.
    expect(CredentialAuditEvent::query()->where('event', LifecycleEventType::SensitiveRead->value)->count())->toBe(0);
});

// ---------------------------------------------------------------- AC6 --

it('renders a headline whose label is in the app declared vocabulary', function (): void {
    vitalsDeclareHeadline(
        ['active-sessions', 'open-cases'],
        new HeadlineStat(128, 'active-sessions', HeadlineUnit::Count),
    );

    $response = $this->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()])
        ->assertOk();

    expect($response->json('headline'))->toBe(['value' => 128, 'label' => 'active-sessions', 'unit' => 'count'])
        ->and($response->json('health'))->toBe('ok');

    $this->assertBuiltForCloudMetadataShape($response->json(), 'GET /bfc/console/vitals with a headline');
});

it('refuses a headline label outside the app declared vocabulary', function (): void {
    vitalsDeclareHeadline(
        ['active-sessions'],
        new HeadlineStat(7, 'Something The Operator Typed', HeadlineUnit::Count),
    );

    $response = $this->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()])
        ->assertOk();

    expect($response->json('headline'))->toBeNull()
        ->and($response->json('health'))->toBe('degraded');

    $this->assertBuiltForCloudMetadataShape($response->json(), 'GET /bfc/console/vitals with a refused headline');
});

it('refuses a headline whose declared vocabulary is itself unbounded', function (): void {
    // A vocabulary is only a bound if its own members are bounded; an app
    // that declares free text as a "vocabulary" gets no headline.
    vitalsDeclareHeadline(
        ['whatever the operator typed today'],
        new HeadlineStat(7, 'whatever the operator typed today'),
    );

    $response = $this->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()])
        ->assertOk();

    expect($response->json('headline'))->toBeNull()
        ->and($response->json('health'))->toBe('degraded');
});

it('gives an app that declares no vocabulary no headline rather than a fabricated one', function (): void {
    // Declaring the interface with an EMPTY vocabulary, and reporting a
    // stat anyway: still nothing on the wire.
    vitalsDeclareHeadline([], new HeadlineStat(1, 'anything'));

    expect($this->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()])
        ->assertOk()
        ->json('headline'))->toBeNull();

    // And an app that does not implement the interface at all — the
    // package ships no vocabulary of its own, so there is nothing to
    // fall back to.
    HeadlineDeclaration::reset();
    app()->forgetInstance(CredentialDeclaration::class);
    app()->bind(CredentialDeclaration::class, DefaultCredentialDeclaration::class);

    $response = $this->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()])
        ->assertOk();

    expect($response->json('headline'))->toBeNull()
        ->and($response->json('health'))->toBe('ok');
});

it('reports no headline and degrades when the app declaration throws', function (): void {
    HeadlineDeclaration::$throws = new RuntimeException('the stat source is down');
    app()->bind(CredentialDeclaration::class, HeadlineDeclaration::class);

    $response = $this->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()])
        ->assertOk();

    expect($response->json('headline'))->toBeNull()
        ->and($response->json('health'))->toBe('degraded');
});

// ---------------------------------------------------------------- AC7 --

it('degrades honestly instead of erroring when the queue store is unreachable', function (): void {
    // A queue connection pointing at a database that cannot be opened —
    // the in-process shape of "the dependency is unreachable", with no
    // network wait and no ambiguity about which read failed.
    config([
        'database.connections.unreachable' => ['driver' => 'sqlite', 'database' => '/nonexistent/bfc/queue.sqlite'],
        'queue.connections.database.connection' => 'unreachable',
        'built-for-cloud.vitals.app_version' => '1.4.2',
    ]);

    $response = $this->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()]);

    $response->assertOk();

    expect($response->json('health'))->toBe('degraded')
        ->and($response->json('queue.pending'))->toBeNull()
        ->and($response->json('queue.reserved'))->toBeNull()
        ->and($response->json('queue.oldest_pending_age_seconds'))->toBeNull()
        // Everything it COULD fill is still filled — that is the whole
        // point of degrading rather than erroring (D9).
        ->and($response->json('api_version'))->toBe(BuiltForCloud::API_VERSION)
        ->and($response->json('bfc_version'))->toBe(BuiltForCloud::VERSION)
        ->and($response->json('app_version'))->toBe('1.4.2')
        // The failed-job count rides a different connection and is
        // unaffected: partial degradation stays partial.
        ->and($response->json('queue.failed'))->toBe(0);

    $this->assertBuiltForCloudMetadataShape($response->json(), 'GET /bfc/console/vitals degraded');
});

it('degrades rather than echoing an app version this endpoint cannot bound', function (): void {
    config(['built-for-cloud.vitals.app_version' => 'Release Candidate (Tuesday)']);

    $response = $this->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()])
        ->assertOk();

    expect($response->json('app_version'))->toBeNull()
        ->and($response->json('health'))->toBe('degraded');

    $this->assertBuiltForCloudMetadataShape($response->json(), 'GET /bfc/console/vitals with a refused app_version');
});

it('degrades rather than erroring on an unparseable declared deploy time', function (): void {
    config(['built-for-cloud.vitals.deployed_at' => 'whenever we last shipped']);

    $response = $this->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()])
        ->assertOk();

    expect($response->json('deployed_at'))->toBeNull()
        ->and($response->json('deploy_age_seconds'))->toBeNull()
        ->and($response->json('health'))->toBe('degraded');
});

it('reports what a non-database queue driver can tell it and nothing more', function (): void {
    // Only the `database` driver exposes the pending/reserved split and
    // an enqueue time to the package. Every other driver reports depth
    // and nulls the rest — a limitation, not a fault, so health stays
    // `ok` rather than degrading on every redis or sqs app in the fleet.
    config([
        'queue.default' => 'sync',
        'queue.connections.sync' => ['driver' => 'sync'],
    ]);

    $response = $this->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()])
        ->assertOk();

    expect($response->json('health'))->toBe('ok')
        ->and($response->json('queue.pending'))->toBe(0)
        ->and($response->json('queue.reserved'))->toBeNull()
        ->and($response->json('queue.oldest_pending_age_seconds'))->toBeNull()
        ->and($response->json('queue.failed'))->toBe(0);
});

it('refuses a non-finite headline value', function (): void {
    vitalsDeclareHeadline(['active-sessions'], new HeadlineStat(NAN, 'active-sessions', HeadlineUnit::Count));

    $response = $this->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()])
        ->assertOk();

    expect($response->json('headline'))->toBeNull()
        ->and($response->json('health'))->toBe('degraded');
});

it('reports a negative deploy age rather than hiding clock skew', function (): void {
    config(['built-for-cloud.vitals.deployed_at' => now()->addHour()->toAtomString()]);

    $response = $this->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()])
        ->assertOk();

    expect($response->json('deploy_age_seconds'))->toBeLessThan(0)
        ->and($response->json('deployed_at'))->not->toBeNull();
});

it('refuses with a bounded 401 on an app that never registered the bfc guard', function (): void {
    // A package-mounted route may not depend on the consuming app having
    // configured a guard: without this the AuthManager throws and every
    // request here — authenticated or not — is a 500.
    config(['auth.guards.bfc' => null]);

    $this->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()])
        ->assertUnauthorized();

    $this->getJson('/bfc/console/vitals')->assertUnauthorized();
});

// ---------------------------------------------------------------- AC8 --

it('renders honestly for a caller stating a previous contract version', function (): void {
    $response = $this->getJson('/bfc/console/vitals', [
        'Authorization' => vitalsReader()->bearerHeader(),
        ConsoleVitals::CONTRACT_VERSION_HEADER => (string) (BuiltForCloud::API_VERSION - 1),
    ]);

    $response->assertOk();

    expect($response->json('health'))->toBe('degraded')
        // The skew is RENDERABLE: the caller is told what this app
        // actually speaks, rather than being handed an error it cannot
        // display (D9).
        ->and($response->json('api_version'))->toBe(BuiltForCloud::API_VERSION)
        ->and($response->json('bfc_version'))->toBe(BuiltForCloud::VERSION);

    // A caller stating the CURRENT version is not degraded — otherwise
    // the assertion above would pass on a route that always degrades.
    $agreed = $this->getJson('/bfc/console/vitals', [
        'Authorization' => vitalsReader()->bearerHeader(),
        ConsoleVitals::CONTRACT_VERSION_HEADER => (string) BuiltForCloud::API_VERSION,
    ])->assertOk();

    expect($agreed->json('health'))->toBe('ok');
});

// ---------------------------------------------------------------- AC9 --

it('audits every vitals read with the actor typed, ids only', function (): void {
    $reader = vitalsReader();

    $this->getJson('/bfc/console/vitals', ['Authorization' => $reader->bearerHeader()])->assertOk();

    $reads = CredentialAuditEvent::query()
        ->where('event', LifecycleEventType::SensitiveRead->value)
        ->get();

    expect($reads)->toHaveCount(1)
        ->and($reads[0]->actor_type)->toBe(AuditActorType::OperatorIntegration)
        ->and($reads[0]->actor_ref)->toBe($reader->credential->id)
        ->and($reads[0]->credential_id)->toBe($reader->credential->id)
        ->and((string) $reads[0]->note)->toContain('/bfc/console/vitals')
        ->and((string) $reads[0]->note)->not->toContain($reader->plaintext());

    // A degraded read is audited exactly like a healthy one — the audit
    // records the READ, not the health.
    config(['built-for-cloud.vitals.app_version' => 'not a version']);

    $this->getJson('/bfc/console/vitals', ['Authorization' => $reader->bearerHeader()])
        ->assertOk()
        ->assertJsonPath('health', 'degraded');

    expect(CredentialAuditEvent::query()->where('event', LifecycleEventType::SensitiveRead->value)->count())->toBe(2);
});

// --------------------------------------------------------------- AC10 --

it('rate-limits the vitals route per credential and per ip', function (): void {
    $reader = vitalsReader();

    foreach (range(1, 60) as $ignored) {
        $this->withServerVariables(['REMOTE_ADDR' => '10.9.0.1'])
            ->getJson('/bfc/console/vitals', ['Authorization' => $reader->bearerHeader()])
            ->assertOk();
    }

    // The 61st read from that credential is throttled — and from a
    // DIFFERENT address too, so a stolen dashboard credential is bounded
    // across every IP it is replayed from.
    $this->withServerVariables(['REMOTE_ADDR' => '10.9.0.1'])
        ->getJson('/bfc/console/vitals', ['Authorization' => $reader->bearerHeader()])
        ->assertStatus(429);

    $this->withServerVariables(['REMOTE_ADDR' => '10.9.0.2'])
        ->getJson('/bfc/console/vitals', ['Authorization' => $reader->bearerHeader()])
        ->assertStatus(429);

    // A different credential from a fresh address still reads: the
    // buckets are independent, not one compound key.
    $this->withServerVariables(['REMOTE_ADDR' => '10.9.0.3'])
        ->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()])
        ->assertOk();
});

it('registers both vitals limits', function (): void {
    // Unit-level, so deleting either bound reds this without driving
    // hundreds of requests.
    $limiter = RateLimiter::limiter('bfc-vitals');

    expect($limiter)->not->toBeNull();

    $request = Request::create('/bfc/console/vitals', 'GET', server: [
        'REMOTE_ADDR' => '9.9.9.9',
        'HTTP_AUTHORIZATION' => 'Bearer probe-secret',
    ]);

    /** @var list<Limit> $limits */
    $limits = $limiter($request);

    $byKey = collect($limits)->keyBy(fn (Limit $limit): string => (string) $limit->key);

    expect($limits)->toHaveCount(2)
        ->and($byKey->has('bfc-vitals-cred|'.hash('sha256', 'probe-secret')))->toBeTrue()
        ->and($byKey->get('bfc-vitals-cred|'.hash('sha256', 'probe-secret'))->maxAttempts)->toBe(60)
        ->and($byKey->has('bfc-vitals-ip|9.9.9.9'))->toBeTrue()
        ->and($byKey->get('bfc-vitals-ip|9.9.9.9')->maxAttempts)->toBe(120);
});

// --------------------------------------------------------------- AC12 --

it('advertises the vitals surface in the meta capabilities', function (): void {
    expect($this->getJson('/bfc/meta')->assertOk()->json('capabilities'))
        ->toContain('console-vitals');
});
