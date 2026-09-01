<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\AuditActorType;
use ArtisanBuild\BuiltForCloud\BuiltForCloud;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Contracts\DeclaresHeadlineStat;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialOutboxEntry;
use ArtisanBuild\BuiltForCloud\DefaultCredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ConsoleVitals;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureDashboardCredential;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\ContractAssertions;
use ArtisanBuild\BuiltForCloud\Testing\MintedTestCredential;
use ArtisanBuild\BuiltForCloud\Testing\WithCredentials;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\ForeignHeadlineLabel;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\HeadlineDeclaration;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\NotAnEnumHeadlineDeclaration;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\NoVocabularyHeadlineDeclaration;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\OversizedHeadlineDeclaration;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\OversizedHeadlineLabel;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\RefusingDeclaration;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\SinkHeadlineLabel;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\UnboundedHeadlineDeclaration;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\UnboundedHeadlineLabel;
use ArtisanBuild\BuiltForCloud\Vitals\HeadlineStat;
use ArtisanBuild\BuiltForCloud\Vitals\HeadlineUnit;
use ArtisanBuild\BuiltForCloud\Vitals\VitalsPayload;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Routing\Route as RoutingRoute;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;

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
        // Without a stable deployment identifier the queue snapshot is
        // not cached at all (a shared cache with no identity mixes
        // deployments), so the harness names one.
        'built-for-cloud.vitals.deployment_id' => 'deployment-under-test',
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
    RefusingDeclaration::$refuse = [];
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
 * Bind a headline-declaring fixture as the app's contract declaration.
 *
 * The VOCABULARY is chosen by picking a declaration class, not by
 * setting a value — DeclaresHeadlineStat::HEADLINE_VOCABULARY is a class
 * constant, so a test cannot vary it any more than an app can. Only the
 * current stat is passed in, because only the current stat is a runtime
 * value.
 *
 * @param  class-string<HeadlineDeclaration>  $declaration
 */
function vitalsDeclareHeadline(string $declaration, ?HeadlineStat $stat): void
{
    HeadlineDeclaration::$stat = $stat;

    app()->bind(CredentialDeclaration::class, $declaration);
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

    // And certified against the shipped fail-closed schema, which pins
    // the exact key set — an extra field appearing here is a failure,
    // not something a lexical filter has to recognise as free text.
    $this->assertBuiltForCloudMetadataEndpoint($response, 'GET /bfc/console/vitals');
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

it('ages the oldest pending job per request, not per snapshot', function (): void {
    // The cached snapshot stores the job's raw created_at TIMESTAMP; the
    // age is derived on every poll from the current clock. A refactor
    // that cached the DERIVED age instead would look identical on a
    // single read — the number is right on the first poll — and would
    // then freeze: every later poll would report the age as of the
    // snapshot. Two polls across a time jump are what can see it.
    config(['built-for-cloud.vitals.queue_cache_seconds' => 300]);

    DB::table('jobs')->insert([
        ['queue' => 'default', 'payload' => '{}', 'attempts' => 0, 'reserved_at' => null, 'available_at' => now()->getTimestamp(), 'created_at' => now()->subSeconds(90)->getTimestamp()],
    ]);

    $first = $this->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()])
        ->assertOk()
        ->json('queue.oldest_pending_age_seconds');

    $this->travel(60)->seconds();

    $second = $this->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()])
        ->assertOk()
        ->json('queue.oldest_pending_age_seconds');

    // The SAME cached snapshot, sixty seconds later: the age grew, so
    // the number was derived per request from the stored timestamp.
    expect($first)->toBeGreaterThanOrEqual(90)
        ->and($second)->toBeGreaterThanOrEqual($first + 55);
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

    // And the deprecated env pseudo-credential. Two things refuse it and
    // only one of them is load-bearing: the `bfc` guard has no code path
    // to the fallback store, AND the gate refuses a bearer colliding
    // with the configured fallback before anything resolves. These bytes
    // are not a credential either way, so this case is the weak one; the
    // aliasing tests below are the case that matters.
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

    // THE POSITIVE CONTROL, in this test rather than another file: a
    // gate mutated to abort(401) unconditionally satisfies every
    // assertion above, because "all four answers are identical 401s" is
    // exactly what such a gate produces. A live reader must still read.
    $this->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()])
        ->assertOk()
        ->assertJsonPath('api_version', BuiltForCloud::API_VERSION);
});

// ---------------------------------------------------------------- AC19 --

/**
 * D16 requires the dashboard credential to be unable to touch mutating
 * surfaces. A credential whose BYTES are also the fallback token, or are
 * on file in the legacy `api_tokens` store, can touch them — the
 * aliasing does it, not the credential's own abilities list. So the
 * alias is refused, before anything resolves.
 */
it('refuses a bearer that is also the configured fallback token', function (): void {
    $reader = vitalsReader();

    // The positive control first: these exact bytes read fine.
    $this->getJson('/bfc/console/vitals', ['Authorization' => $reader->bearerHeader()])->assertOk();

    // Now the SAME bytes are also the fallback pseudo-credential, which
    // is admin-equivalent on the legacy surfaces.
    config(['built-for-cloud.fallback_token' => $reader->plaintext()]);

    // Snapshot the row AFTER the control read, so what is compared is
    // what the REFUSAL did, not what the control did.
    $before = $reader->credential->refresh()->getAttributes();

    $refused = $this->getJson('/bfc/console/vitals', ['Authorization' => $reader->bearerHeader()]);

    $refused->assertUnauthorized();

    // Indistinguishable from an unknown bearer: telling a caller "these
    // bytes are also something else" is what an aliasing probe wants.
    expect($refused->getContent())
        ->toBe($this->getJson('/bfc/console/vitals', ['Authorization' => 'Bearer nope-'.bin2hex(random_bytes(16))])->getContent());

    // And side-effect-free: the refusal resolved nothing, so it stamped
    // no usage and touched no column on the credential it declined to
    // authenticate.
    expect($reader->credential->refresh()->getAttributes())->toBe($before);
});

it('refuses a bearer that is also a legacy api_tokens secret', function (): void {
    $reader = vitalsReader();

    $this->getJson('/bfc/console/vitals', ['Authorization' => $reader->bearerHeader()])->assertOk();

    // The same bytes filed in the legacy store, where an admin-scoped
    // row is admin-equivalent on every operator verb.
    ApiToken::query()->create([
        'name' => 'owner',
        'token_hash' => hash('sha256', $reader->plaintext()),
        'abilities' => [Scope::Admin->value],
    ]);

    $this->getJson('/bfc/console/vitals', ['Authorization' => $reader->bearerHeader()])->assertUnauthorized();
});

it('refuses an aliased bearer even when the legacy row is revoked', function (): void {
    $reader = vitalsReader();

    ApiToken::query()->create([
        'name' => 'retired',
        'token_hash' => hash('sha256', $reader->plaintext()),
        'abilities' => [Scope::Admin->value],
        'revoked_at' => now(),
    ]);

    // A revoked row cannot act today, but the question is not "can these
    // bytes act elsewhere right now" — it is whether this deployment has
    // ever filed them as something else. It has, and a row can be
    // un-revoked by anyone who could revoke it.
    $this->getJson('/bfc/console/vitals', ['Authorization' => $reader->bearerHeader()])->assertUnauthorized();

    // A DIFFERENT credential is unaffected: the check is on the bytes,
    // not a blanket refusal once any legacy row exists.
    $this->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()])->assertOk();
});

// --------------------------------------------------------- AC13/AC14 --

/**
 * D16 asks for EXCLUSIVITY, not membership: the dashboard credential is
 * "least-privilege, read-audited, unable to touch content-classified or
 * mutating surfaces". A credential that also holds `credential:admin`
 * reads the dashboard AND mutates every operator surface, so inability
 * has to be a property of the credential, not of the route.
 */
it('refuses a credential that holds metadata:read alongside another ability', function (): void {
    $combined = $this->mintCredential([
        'subject_type' => SubjectType::Operator,
        'subject_ref' => 'combined',
        'abilities' => [OperatorAbility::MetadataRead->value, OperatorAbility::ADMIN],
    ]);

    $this->getJson('/bfc/console/vitals', ['Authorization' => $combined->bearerHeader()])->assertForbidden();

    // The combination is refused HERE, on the dashboard read. It is not
    // refused at mint, and the credential keeps every other authority it
    // names — asserted so the boundary of this fix is a fact rather than
    // a claim in a docblock.
    $this->getJson('/bfc/credentials', ['Authorization' => $combined->bearerHeader()])->assertOk();

    // A narrower combination is refused too: the rule is "exactly
    // metadata:read", not "nothing admin-equivalent".
    $alsoRead = $this->mintCredential([
        'subject_type' => SubjectType::Operator,
        'subject_ref' => 'combined-read',
        'abilities' => [OperatorAbility::MetadataRead->value, OperatorAbility::CredentialRead->value],
    ]);

    $this->getJson('/bfc/console/vitals', ['Authorization' => $alsoRead->bearerHeader()])->assertForbidden();

    // Order does not matter — the check is on the SET.
    $reordered = $this->mintCredential([
        'subject_type' => SubjectType::Operator,
        'subject_ref' => 'reordered',
        'abilities' => [OperatorAbility::ADMIN, OperatorAbility::MetadataRead->value],
    ]);

    $this->getJson('/bfc/console/vitals', ['Authorization' => $reordered->bearerHeader()])->assertForbidden();

    // Positive control: the exclusive credential still reads.
    $this->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()])->assertOk();
});

it('refuses a non-operator subject holding metadata:read, and admits an operator one', function (): void {
    // The contract heads this route "operator credential"; until the
    // exclusivity gate landed, nothing checked the subject at all.
    foreach ([SubjectType::Application, SubjectType::ExternalConsumer, SubjectType::UserPrincipal] as $subjectType) {
        $wrongSubject = $this->mintCredential([
            'subject_type' => $subjectType,
            'subject_ref' => 'subject-'.bin2hex(random_bytes(4)),
            'abilities' => [OperatorAbility::MetadataRead->value],
        ]);

        $this->getJson('/bfc/console/vitals', ['Authorization' => $wrongSubject->bearerHeader()])
            ->assertForbidden();
    }

    $this->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()])->assertOk();
});

it('audits an exclusivity refusal with the acting credential', function (): void {
    $combined = $this->mintCredential([
        'subject_type' => SubjectType::Operator,
        'subject_ref' => 'combined',
        'abilities' => [OperatorAbility::MetadataRead->value, OperatorAbility::ADMIN],
    ]);

    $this->getJson('/bfc/console/vitals', ['Authorization' => $combined->bearerHeader()])->assertForbidden();

    $denied = CredentialAuditEvent::query()
        ->where('event', LifecycleEventType::DeniedAction->value)
        ->get();

    expect($denied)->toHaveCount(1)
        ->and($denied[0]->actor_type)->toBe(AuditActorType::OperatorIntegration)
        ->and($denied[0]->actor_ref)->toBe($combined->credential->id)
        ->and((string) $denied[0]->note)->toContain('and nothing else')
        ->and((string) $denied[0]->note)->not->toContain($combined->plaintext());
});

// ---------------------------------------------------------------- AC6 --

it('renders a headline whose label is in the app declared vocabulary', function (): void {
    vitalsDeclareHeadline(
        HeadlineDeclaration::class,
        new HeadlineStat(128, SinkHeadlineLabel::ActiveSessions, HeadlineUnit::Count),
    );

    $response = $this->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()])
        ->assertOk();

    expect($response->json('headline'))->toBe(['value' => 128, 'label' => 'active-sessions', 'unit' => 'count'])
        ->and($response->json('health'))->toBe('ok');

    $this->assertBuiltForCloudMetadataEndpoint($response, 'GET /bfc/console/vitals');
});

it('refuses a headline label outside the app declared vocabulary', function (): void {
    // The label is an enum case, so it cannot be free text — but it can
    // still come from an enum this app never declared, which is the
    // enum-typed shape of the same mistake.
    vitalsDeclareHeadline(
        HeadlineDeclaration::class,
        new HeadlineStat(7, ForeignHeadlineLabel::SomeoneElsesLabel, HeadlineUnit::Count),
    );

    $response = $this->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()])
        ->assertOk();

    expect($response->json('headline'))->toBeNull()
        ->and($response->json('health'))->toBe('degraded');

    $this->assertBuiltForCloudMetadataEndpoint($response, 'GET /bfc/console/vitals');
});

it('refuses a headline whose declared vocabulary is itself unbounded', function (): void {
    // A vocabulary is only a bound if its own members are bounded; an app
    // that declares free text as a "vocabulary" gets no headline.
    vitalsDeclareHeadline(
        UnboundedHeadlineDeclaration::class,
        new HeadlineStat(7, UnboundedHeadlineLabel::Whatever),
    );

    $response = $this->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()])
        ->assertOk();

    expect($response->json('headline'))->toBeNull()
        ->and($response->json('health'))->toBe('degraded');
});

it('gives an app that declares no vocabulary no headline rather than a fabricated one', function (): void {
    // Declaring the interface with an EMPTY vocabulary, and reporting a
    // stat anyway: still nothing on the wire.
    vitalsDeclareHeadline(NoVocabularyHeadlineDeclaration::class, new HeadlineStat(1, SinkHeadlineLabel::ActiveSessions));

    $contradiction = $this->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()])
        ->assertOk();

    // Reporting a stat while declaring NO vocabulary is a contradiction
    // in the app's own declaration, so it degrades as well as dropping
    // the field — the operator should see that the app asked for
    // something its declaration does not permit.
    expect($contradiction->json('headline'))->toBeNull()
        ->and($contradiction->json('health'))->toBe('degraded');

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

it('refuses a vocabulary larger than the declared cap', function (): void {
    vitalsDeclareHeadline(
        OversizedHeadlineDeclaration::class,
        new HeadlineStat(3, OversizedHeadlineLabel::Label1, HeadlineUnit::Count),
    );

    // Every case is a bounded identifier and the set is compile-time —
    // the cap is about a vocabulary a reviewer can actually review, and
    // it is enforced rather than described.
    $response = $this->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()])
        ->assertOk();

    expect(count(OversizedHeadlineLabel::cases()))->toBe(DeclaresHeadlineStat::MAX_LABELS + 1)
        ->and($response->json('headline'))->toBeNull()
        ->and($response->json('health'))->toBe('degraded');
});

it('refuses a declared vocabulary that is not an enum at all', function (): void {
    // PHP enforces only `?string` on the constant, so an app CAN name a
    // class that is not an enum. The runtime checks, not the type, are
    // what refuse it.
    vitalsDeclareHeadline(NotAnEnumHeadlineDeclaration::class, new HeadlineStat(3, SinkHeadlineLabel::ActiveSessions));

    $response = $this->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()])
        ->assertOk();

    expect($response->json('headline'))->toBeNull()
        ->and($response->json('health'))->toBe('degraded');
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

    $this->assertBuiltForCloudMetadataEndpoint($response, 'GET /bfc/console/vitals');
});

it('degrades rather than echoing an app version this endpoint cannot bound', function (): void {
    config(['built-for-cloud.vitals.app_version' => 'Release Candidate (Tuesday)']);

    $response = $this->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()])
        ->assertOk();

    expect($response->json('app_version'))->toBeNull()
        ->and($response->json('health'))->toBe('degraded');

    $this->assertBuiltForCloudMetadataEndpoint($response, 'GET /bfc/console/vitals');
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
    vitalsDeclareHeadline(HeadlineDeclaration::class, new HeadlineStat(NAN, SinkHeadlineLabel::ActiveSessions, HeadlineUnit::Count));

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

it('audits every vitals read with the actor typed, and accounts for every column on the row', function (): void {
    // The earlier revision claimed this row was "ids only". It is not:
    // the stream's standard provenance columns carry this instance's
    // operator-authored product name, its cloud application name and its
    // environment, on EVERY event. Rather than trust the claim, every
    // populated column is asserted here, so what the row holds is a
    // checked fact and the narrowed claim ("no request or response body,
    // no presented secret, no credential material") is the one the
    // docblock and the contract now make.
    config([
        'built-for-cloud.product' => 'Acme Patient Portal',
        'built-for-cloud.cloud.application' => 'app-1234',
    ]);

    $reader = vitalsReader();

    $this->getJson('/bfc/console/vitals', ['Authorization' => $reader->bearerHeader()])->assertOk();

    $reads = CredentialAuditEvent::query()
        ->where('event', LifecycleEventType::SensitiveRead->value)
        ->get();

    expect($reads)->toHaveCount(1);

    $row = $reads[0];

    // Populated, and exactly these.
    expect($row->actor_type)->toBe(AuditActorType::OperatorIntegration)
        ->and($row->actor_ref)->toBe($reader->credential->id)
        ->and($row->credential_id)->toBe($reader->credential->id)
        ->and($row->provider)->toBe('Acme Patient Portal')
        ->and($row->deployment)->toBe('app-1234')
        ->and($row->environment)->toBe('testing')
        ->and((string) $row->note)->toBe('console vitals read (GET /bfc/console/vitals)')
        ->and($row->occurred_at)->not->toBeNull();

    // Empty, and exactly these.
    expect($row->code_id)->toBeNull()
        ->and($row->superseded_by_credential_id)->toBeNull()
        ->and($row->recipient)->toBeNull()
        ->and($row->code_ttl_seconds)->toBeNull()
        ->and($row->credential_expires_at)->toBeNull()
        ->and($row->reason_code)->toBeNull();

    // EVERY column is accounted for, and the roll-call is DERIVED from
    // the schema rather than hand-written — a hand-written list of 14 of
    // 17 columns would not have noticed a fifteenth arriving, which is
    // exactly the gap that made the old test name ("exactly the declared
    // columns") wider than what it drove. A new column on
    // `credential_audit_events` now reds this until someone decides
    // which list it belongs in.
    $asserted = [
        // Populated above.
        'actor_type', 'actor_ref', 'credential_id', 'provider', 'deployment',
        'environment', 'note', 'occurred_at',
        // Empty above.
        'code_id', 'superseded_by_credential_id', 'recipient', 'code_ttl_seconds',
        'credential_expires_at', 'reason_code',
        // Structural, and asserted by the query and the count above
        // rather than by a value: the row's identity, the event name the
        // query filters on, and the insert stamp.
        'id', 'event', 'created_at',
    ];

    $columns = Schema::getColumnListing('credential_audit_events');

    sort($asserted);
    sort($columns);

    expect($asserted)->toBe($columns);

    // The narrowed claim, driven: no presented secret and no credential
    // material anywhere on the row.
    expect(json_encode($row->getAttributes()))->not->toContain($reader->plaintext())
        ->and(json_encode($row->getAttributes()))->not->toContain($reader->credential->secret_hash);

    // A degraded read is audited exactly like a healthy one — the audit
    // records the READ, not the health.
    config(['built-for-cloud.vitals.app_version' => 'not a version']);

    $this->getJson('/bfc/console/vitals', ['Authorization' => $reader->bearerHeader()])
        ->assertOk()
        ->assertJsonPath('health', 'degraded');

    expect(CredentialAuditEvent::query()->where('event', LifecycleEventType::SensitiveRead->value)->count())->toBe(2);
});

// --------------------------------------------------------------- AC10 --

it('rate-limits the vitals route per credential', function (): void {
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

it('rate-limits the vitals route per ip across credentials', function (): void {
    // The per-IP bound is 300/minute, five times the per-credential 60,
    // so exhausting it takes five saturated readers. Driven rather than
    // named: an earlier revision's test title said "per credential and
    // per ip" while only the credential bound and bucket independence
    // were behavioural, and the IP number lived solely in the unit test
    // below.
    foreach (range(1, 5) as $ignored) {
        $reader = vitalsReader();

        foreach (range(1, 60) as $ignored2) {
            $this->withServerVariables(['REMOTE_ADDR' => '10.7.0.1'])
                ->getJson('/bfc/console/vitals', ['Authorization' => $reader->bearerHeader()])
                ->assertOk();
        }
    }

    // A SIXTH credential, with an untouched bucket of its own, is
    // throttled from that address: the 300 are spent.
    $fresh = vitalsReader();

    $this->withServerVariables(['REMOTE_ADDR' => '10.7.0.1'])
        ->getJson('/bfc/console/vitals', ['Authorization' => $fresh->bearerHeader()])
        ->assertStatus(429);

    // …and reads immediately from a different address, which is what
    // makes the 429 above the IP bound rather than its own.
    $this->withServerVariables(['REMOTE_ADDR' => '10.7.0.2'])
        ->getJson('/bfc/console/vitals', ['Authorization' => $fresh->bearerHeader()])
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
        ->and($byKey->get('bfc-vitals-ip|9.9.9.9')->maxAttempts)->toBe(300);
});

// ------------------------------------------------------- the one gate --

it('mounts exactly one gate on the vitals route', function (): void {
    $route = collect(Route::getRoutes()->getRoutes())
        ->first(fn (RoutingRoute $candidate): bool => $candidate->uri() === 'bfc/console/vitals');

    expect($route)->not->toBeNull()
        ->and($route->gatherMiddleware())->toBe(['throttle:bfc-vitals', EnsureDashboardCredential::class]);

    // `bfc.ability` sat in front of this gate for one revision. It
    // enforced a strict SUBSET, so it never changed an answer — while
    // its own denial audit drained the delivery outbox, putting the
    // amplification lever back in front of the hardening. A redundant
    // gate is a second code path with its own side effects.
    expect($route->gatherMiddleware())
        ->each(fn ($middleware) => $middleware->not->toContain('bfc.ability'));
});

it('honours the app declaration refusing the dashboard ability', function (): void {
    // The hook `bfc.ability` used to call is kept, because an app that
    // narrows its own credentials must be able to narrow this one.
    config(['built-for-cloud.credentials.declaration' => RefusingDeclaration::class]);

    RefusingDeclaration::$refuse = [OperatorAbility::MetadataRead->value];

    $this->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()])
        ->assertForbidden();

    $denied = CredentialAuditEvent::query()
        ->where('event', LifecycleEventType::DeniedAction->value)
        ->get();

    expect($denied)->toHaveCount(1)
        ->and($denied[0]->actor_type)->toBe(AuditActorType::OperatorIntegration)
        ->and((string) $denied[0]->note)->toContain('app declaration refused');

    // The positive control: with the declaration allowing it, the same
    // credential reads.
    RefusingDeclaration::$refuse = [];

    $this->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()])->assertOk();
});

// --------------------------------------------------------- polling --

it('never drains the outbox from the polled read', function (): void {
    // A drain is O(claimable rows) and may SEND MAIL. Hanging one off a
    // route the vendor polls sixty times a minute per credential turns a
    // dashboard into a database and mail amplifier, so this event is
    // recorded with the drain suppressed.
    //
    // Driven through a real undelivered row: an ordinary mutating verb
    // leaves one behind, and the vitals read must leave it exactly
    // where it found it.
    $admin = $this->mintCredential([
        'subject_type' => SubjectType::Operator,
        'subject_ref' => 'control-plane',
        'abilities' => [OperatorAbility::ADMIN],
    ]);

    $this->postJson('/bfc/credentials', [
        'subject_type' => 'external_consumer',
        'subject_ref' => 'acme',
    ], ['Authorization' => $admin->bearerHeader()])->assertCreated();

    // Warm the reader first. A credential's FIRST presentation emits
    // `first_used` — a genuine state transition that predates this route
    // and legitimately drains — and it happens once per credential, not
    // once per poll. What this test is about is the STEADY STATE: the
    // second and every later poll.
    $reader = vitalsReader();

    $this->getJson('/bfc/console/vitals', ['Authorization' => $reader->bearerHeader()])->assertOk();

    // Make every existing row claimable-but-undelivered again, and count
    // what a drain would have to walk.
    CredentialOutboxEntry::query()->update(['delivered_at' => null, 'claimed_at' => null, 'claim_token' => null]);

    $before = CredentialOutboxEntry::query()->whereNull('delivered_at')->count();

    expect($before)->toBeGreaterThan(0);

    $this->getJson('/bfc/console/vitals', ['Authorization' => $reader->bearerHeader()])->assertOk();

    // The vitals read added its OWN outbox row (the append is still
    // transactional) and delivered nothing — including nothing that was
    // already waiting.
    expect(CredentialOutboxEntry::query()->whereNull('delivered_at')->count())->toBe($before + 1)
        ->and(CredentialOutboxEntry::query()->whereNotNull('claimed_at')->count())->toBe(0);
});

it('never drains the outbox from a refused poll either', function (): void {
    // The DENIAL branch is the one an attacker reaches at will, so it is
    // the branch that most needed this. It is also where the hole moved
    // last round: an outer `bfc.ability` gate refused a
    // wrong-ability credential and drained on the way out.
    $admin = $this->mintCredential([
        'subject_type' => SubjectType::Operator,
        'subject_ref' => 'control-plane',
        'abilities' => [OperatorAbility::ADMIN],
    ]);

    $this->postJson('/bfc/credentials', [
        'subject_type' => 'external_consumer',
        'subject_ref' => 'acme',
    ], ['Authorization' => $admin->bearerHeader()])->assertCreated();

    // A credential that authenticates and is refused. Warmed first, so
    // the once-per-credential `first_used` transition is not what we
    // are measuring.
    $wrongAbility = $this->mintCredential([
        'subject_type' => SubjectType::Operator,
        'subject_ref' => 'reader',
        'abilities' => [OperatorAbility::CredentialRead->value],
    ]);

    $this->getJson('/bfc/console/vitals', ['Authorization' => $wrongAbility->bearerHeader()])->assertForbidden();

    CredentialOutboxEntry::query()->update(['delivered_at' => null, 'claimed_at' => null, 'claim_token' => null]);

    $before = CredentialOutboxEntry::query()->whereNull('delivered_at')->count();

    expect($before)->toBeGreaterThan(0);

    foreach (range(1, 3) as $ignored) {
        $this->getJson('/bfc/console/vitals', ['Authorization' => $wrongAbility->bearerHeader()])
            ->assertForbidden();
    }

    // Three refusals, three denial audits, and not one delivery.
    expect(CredentialOutboxEntry::query()->whereNull('delivered_at')->count())->toBe($before + 3)
        ->and(CredentialOutboxEntry::query()->whereNotNull('claimed_at')->count())->toBe(0);
});

it('serves repeat polls from one cached queue snapshot', function (): void {
    $reader = vitalsReader();

    $this->getJson('/bfc/console/vitals', ['Authorization' => $reader->bearerHeader()])
        ->assertOk()
        ->assertJsonPath('queue.pending', 0);

    // A job enqueued INSIDE the cache window is deliberately not visible
    // yet: the snapshot is what bounds a one-second poll to one read per
    // window, and a cache that revalidated per request would not bound
    // anything.
    DB::table('jobs')->insert([
        'queue' => 'default', 'payload' => '{}', 'attempts' => 0,
        'reserved_at' => null, 'available_at' => now()->getTimestamp(), 'created_at' => now()->getTimestamp(),
    ]);

    $this->getJson('/bfc/console/vitals', ['Authorization' => $reader->bearerHeader()])
        ->assertOk()
        ->assertJsonPath('queue.pending', 0);

    // Once the window passes, the next poll reads for real.
    $this->travel(20)->seconds();

    $this->getJson('/bfc/console/vitals', ['Authorization' => $reader->bearerHeader()])
        ->assertOk()
        ->assertJsonPath('queue.pending', 1);
});

it('reports a cached degraded queue as degraded rather than laundering it', function (): void {
    config([
        'database.connections.unreachable' => ['driver' => 'sqlite', 'database' => '/nonexistent/bfc/queue.sqlite'],
        'queue.connections.database.connection' => 'unreachable',
    ]);

    $reader = vitalsReader();

    $this->getJson('/bfc/console/vitals', ['Authorization' => $reader->bearerHeader()])
        ->assertOk()
        ->assertJsonPath('health', 'degraded');

    // The second poll is served from the snapshot, and a cache hit must
    // not turn a failed read into an `ok`.
    $this->getJson('/bfc/console/vitals', ['Authorization' => $reader->bearerHeader()])
        ->assertOk()
        ->assertJsonPath('health', 'degraded')
        ->assertJsonPath('queue.pending', null);
});

it('reads without caching when the snapshot is turned off', function (): void {
    config(['built-for-cloud.vitals.queue_cache_seconds' => 0]);

    $reader = vitalsReader();

    $this->getJson('/bfc/console/vitals', ['Authorization' => $reader->bearerHeader()])
        ->assertOk()
        ->assertJsonPath('queue.pending', 0);

    DB::table('jobs')->insert([
        'queue' => 'default', 'payload' => '{}', 'attempts' => 0,
        'reserved_at' => null, 'available_at' => now()->getTimestamp(), 'created_at' => now()->getTimestamp(),
    ]);

    $this->getJson('/bfc/console/vitals', ['Authorization' => $reader->bearerHeader()])
        ->assertOk()
        ->assertJsonPath('queue.pending', 1);
});

it('never turns a malformed cached snapshot into a 500', function (): void {
    DB::table('jobs')->insert([
        'queue' => 'default', 'payload' => '{}', 'attempts' => 0,
        'reserved_at' => null, 'available_at' => now()->getTimestamp(), 'created_at' => now()->getTimestamp(),
    ]);

    // A stale shape, a colliding key, another package's value: the cache
    // is not a trusted input, and reconstructing from it outside the
    // degradation guard turned a dependency problem into the one thing
    // this route promises cannot happen.
    Cache::shouldReceive('remember')
        ->andReturn(['pending' => '12', 'degraded' => 'yes', 'unexpected' => true]);

    $response = $this->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()])
        ->assertOk();

    // Bypassed, not repaired and not trusted: the numbers are the ones
    // this deployment actually read.
    expect($response->json('queue.pending'))->toBe(1)
        ->and($response->json('health'))->toBe('ok');
});

it('never turns an unavailable cache into a 500', function (): void {
    Cache::shouldReceive('remember')->andThrow(new RuntimeException('the cache store is gone'));

    $this->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()])
        ->assertOk()
        ->assertJsonPath('queue.pending', 0)
        ->assertJsonPath('health', 'ok');
});

it('namespaces the queue snapshot by deployment identity and by the whole queue identity', function (): void {
    $reader = vitalsReader();

    $this->getJson('/bfc/console/vitals', ['Authorization' => $reader->bearerHeader()])
        ->assertOk()
        ->assertJsonPath('queue.pending', 0);

    DB::table('jobs')->insert([
        'queue' => 'default', 'payload' => '{}', 'attempts' => 0,
        'reserved_at' => null, 'available_at' => now()->getTimestamp(), 'created_at' => now()->getTimestamp(),
    ]);

    // Same deployment, same queue, inside the window: the snapshot stands.
    $this->getJson('/bfc/console/vitals', ['Authorization' => $reader->bearerHeader()])
        ->assertOk()
        ->assertJsonPath('queue.pending', 0);

    // A DIFFERENT deployment sharing this cache must not be served the
    // first one's backlog. Two apps behind one Redis with one
    // CACHE_PREFIX is an ordinary staging arrangement, and serving one
    // app's backlog as another's honest local data is worse than a 500.
    config(['built-for-cloud.vitals.deployment_id' => 'another-deployment']);

    $this->getJson('/bfc/console/vitals', ['Authorization' => $reader->bearerHeader()])
        ->assertOk()
        ->assertJsonPath('queue.pending', 1);

    // The QUEUE NAME is part of the identity too. The previous key read
    // only driver/connection/table, so on Redis and SQS — where the
    // queue name is the thing that distinguishes one backlog from
    // another — the queue was absent from the key entirely.
    config(['built-for-cloud.vitals.deployment_id' => 'deployment-under-test', 'queue.connections.database.queue' => 'exports']);

    $this->getJson('/bfc/console/vitals', ['Authorization' => $reader->bearerHeader()])
        ->assertOk()
        ->assertJsonPath('queue.pending', 1);

    // And so is the table.
    config(['queue.connections.database.queue' => 'default', 'queue.connections.database.table' => 'other_jobs']);

    $this->getJson('/bfc/console/vitals', ['Authorization' => $reader->bearerHeader()])
        ->assertOk()
        ->assertJsonPath('queue.pending', null)
        ->assertJsonPath('health', 'degraded');
});

it('shares no cache at all when the deployment cannot be identified', function (): void {
    // The honest failure is slower vitals, not silently mixed ones: with
    // no stable identifier the snapshot is not cached, so every poll
    // reads directly and no two deployments can collide on a key.
    config([
        'built-for-cloud.vitals.deployment_id' => null,
        'built-for-cloud.cloud.application' => null,
        // Deliberately left at their defaults — `product` defaults to a
        // shared literal and the environment is shared too, which is
        // exactly why neither may stand in for an identity.
    ]);

    $reader = vitalsReader();

    $this->getJson('/bfc/console/vitals', ['Authorization' => $reader->bearerHeader()])
        ->assertOk()
        ->assertJsonPath('queue.pending', 0);

    DB::table('jobs')->insert([
        'queue' => 'default', 'payload' => '{}', 'attempts' => 0,
        'reserved_at' => null, 'available_at' => now()->getTimestamp(), 'created_at' => now()->getTimestamp(),
    ]);

    // No window to hide behind: the very next poll reads for real.
    $this->getJson('/bfc/console/vitals', ['Authorization' => $reader->bearerHeader()])
        ->assertOk()
        ->assertJsonPath('queue.pending', 1);

    // `cloud.application` alone is enough to turn caching back on.
    config(['built-for-cloud.cloud.application' => 'app-1234']);

    $this->getJson('/bfc/console/vitals', ['Authorization' => $reader->bearerHeader()])
        ->assertOk()
        ->assertJsonPath('queue.pending', 1);

    DB::table('jobs')->insert([
        'queue' => 'default', 'payload' => '{}', 'attempts' => 0,
        'reserved_at' => null, 'available_at' => now()->getTimestamp(), 'created_at' => now()->getTimestamp(),
    ]);

    $this->getJson('/bfc/console/vitals', ['Authorization' => $reader->bearerHeader()])
        ->assertOk()
        ->assertJsonPath('queue.pending', 1);
});

it('keeps the oldest-job age moving inside a cache window', function (): void {
    DB::table('jobs')->insert([
        'queue' => 'default', 'payload' => '{}', 'attempts' => 0,
        'reserved_at' => null, 'available_at' => now()->getTimestamp(), 'created_at' => now()->subSeconds(30)->getTimestamp(),
    ]);

    $reader = vitalsReader();

    expect($this->getJson('/bfc/console/vitals', ['Authorization' => $reader->bearerHeader()])
        ->assertOk()
        ->json('queue.oldest_pending_age_seconds'))->toBeGreaterThanOrEqual(30);

    // Still inside the window, so the COUNTS are the cached ones — but
    // the age is derived per request from a cached timestamp, and this
    // is the one number on the payload whose entire meaning is that it
    // moves. Caching the computed delta froze it.
    $this->travel(10)->seconds();

    expect($this->getJson('/bfc/console/vitals', ['Authorization' => $reader->bearerHeader()])
        ->assertOk()
        ->json('queue.oldest_pending_age_seconds'))->toBeGreaterThanOrEqual(40);
});

// ----------------------------------------------------- derived bounds --

it('degrades rather than reporting an age outside the window it will report', function (): void {
    config(['built-for-cloud.vitals.deployed_at' => '1901-12-13T20:45:52+00:00']);

    $response = $this->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()])
        ->assertOk();

    expect($response->json('deploy_age_seconds'))->toBeNull()
        // The instant itself is still reported — it parsed; it is the
        // derived age that falls outside the bound.
        ->and($response->json('deployed_at'))->not->toBeNull()
        ->and($response->json('health'))->toBe('degraded');

    $this->assertBuiltForCloudMetadataEndpoint($response, 'GET /bfc/console/vitals');
});

it('degrades rather than reporting a headline magnitude past the bound', function (): void {
    vitalsDeclareHeadline(
        HeadlineDeclaration::class,
        new HeadlineStat(VitalsPayload::MAX_HEADLINE_MAGNITUDE * 10, SinkHeadlineLabel::ActiveSessions, HeadlineUnit::Count),
    );

    $response = $this->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()])
        ->assertOk();

    expect($response->json('headline'))->toBeNull()
        ->and($response->json('health'))->toBe('degraded');

    // The value AT the bound is reported: the bound is inclusive, and a
    // test that only drove the refusal could not tell a bound from a
    // blanket refusal.
    vitalsDeclareHeadline(
        HeadlineDeclaration::class,
        new HeadlineStat(VitalsPayload::MAX_HEADLINE_MAGNITUDE, SinkHeadlineLabel::ActiveSessions, HeadlineUnit::Count),
    );

    expect($this->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()])
        ->assertOk()
        // `toEqual`, not `toBe`: a float with no fractional part
        // round-trips through JSON as an integer.
        ->json('headline.value'))->toEqual(VitalsPayload::MAX_HEADLINE_MAGNITUDE);
});

// ---------------------------------------------------------- AC16/AC17 --

it('throttles refused attempts, so the throttle is provably outside the gate', function (): void {
    // Sixty unauthenticated reads share the `anonymous` credential
    // bucket. If the throttle sat INSIDE the gate, a refused request
    // would never reach it and the 61st would be another 401.
    foreach (range(1, 60) as $ignored) {
        $this->withServerVariables(['REMOTE_ADDR' => '10.8.0.1'])
            ->getJson('/bfc/console/vitals')
            ->assertUnauthorized();
    }

    $this->withServerVariables(['REMOTE_ADDR' => '10.8.0.1'])
        ->getJson('/bfc/console/vitals')
        ->assertStatus(429);

    // A live reader from that address is unaffected: its own credential
    // bucket is untouched, which also proves the 429 above came from the
    // anonymous bucket rather than the IP one.
    $this->withServerVariables(['REMOTE_ADDR' => '10.8.0.1'])
        ->getJson('/bfc/console/vitals', ['Authorization' => vitalsReader()->bearerHeader()])
        ->assertOk();
});

it('refuses to serve a read it cannot audit', function (): void {
    $reader = vitalsReader();

    // The positive control first: this credential reads fine while the
    // audit store is there.
    $this->getJson('/bfc/console/vitals', ['Authorization' => $reader->bearerHeader()])->assertOk();

    // D16's ability is read-audited, so an unauditable vendor read is
    // one this deployment must not serve. This is the ONE thing that can
    // fail this route, and it is deliberate — see the controller.
    Schema::drop('credential_audit_events');

    $this->getJson('/bfc/console/vitals', ['Authorization' => $reader->bearerHeader()])
        ->assertStatus(500);
});

// --------------------------------------------------------------- AC12 --

it('advertises the vitals surface in the meta capabilities', function (): void {
    expect($this->getJson('/bfc/meta')->assertOk()->json('capabilities'))
        ->toContain('console-vitals');
});
