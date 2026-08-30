<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\BuiltForCloud;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyring;
use ArtisanBuild\BuiltForCloud\Contracts\CredentialDeclaration;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\MetadataShape;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\OwnershipClaim;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\ContractAssertions;
use ArtisanBuild\BuiltForCloud\Testing\MetadataEndpointShapes;
use ArtisanBuild\BuiltForCloud\Testing\MintedTestCredential;
use ArtisanBuild\BuiltForCloud\Testing\WithCredentials;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\HeadlineDeclaration;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\SelfServiceDeclaration;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\SinkHeadlineLabel;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\SubstitutingContractConsumer;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\User;
use ArtisanBuild\BuiltForCloud\Vitals\HeadlineUnit;
use ArtisanBuild\BuiltForCloud\Vitals\Health;
use ArtisanBuild\BuiltForCloud\Vitals\VitalsPayload;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Response;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\AssertionFailedError;

uses(RefreshDatabase::class, WithCredentials::class, ContractAssertions::class);

/**
 * Console PRD D15 / docs/http-contract.md "Endpoint classification" —
 * D15 for the endpoints THIS PACKAGE serves, held by ENUMERATION.
 *
 * The general-purpose conformance instrument that used to live here is
 * gone, and the reason is worth keeping written down because it is not a
 * bug that was fixed. If the consuming app supplies the schema, the app
 * decides what counts as free text: it names the fields and the `enum`
 * members, so `note: pending` can be declared a `token` or a permitted
 * member and certified. Four rounds narrowed the type language and
 * closed four escapes; none of them touched that one, because closing a
 * type-name set does not establish value provenance. A general
 * instrument is deferred as its own decision.
 *
 * What is left says only what it does: every metadata-classified route
 * this package serves has its expected 2xx shape written out, and this
 * file drives all of them plus the mutations each must refuse.
 */
function metadataOperator(OperatorAbility $ability): MintedTestCredential
{
    return test()->mintCredential([
        'subject_type' => SubjectType::Operator,
        'subject_ref' => 'op-'.bin2hex(random_bytes(4)),
        'abilities' => [$ability->value],
    ]);
}

function metadataAdminToken(): string
{
    $plaintext = 'metadata-admin-'.bin2hex(random_bytes(16));

    ApiToken::query()->create([
        'name' => 'owner',
        'token_hash' => hash('sha256', $plaintext),
        'abilities' => [Scope::Admin->value],
    ]);

    return $plaintext;
}

/**
 * A response carrying exactly these bytes, so a mutation of a real
 * payload can be put back through the same assertion the route's own
 * response goes through.
 */
function metadataResponse(mixed $body): TestResponse
{
    return new TestResponse(new Response(json_encode($body), 200));
}

/**
 * A payload that satisfies the enumerated vitals shape, as the base for
 * the mutations below — so each rejection differs from a PASSING payload
 * in exactly one way.
 *
 * @return array<string, mixed>
 */
function metadataVitalsBody(): array
{
    return [
        'version' => VitalsPayload::VERSION,
        'api_version' => BuiltForCloud::API_VERSION,
        'bfc_version' => BuiltForCloud::VERSION,
        'app_version' => null,
        'health' => 'ok',
        'deployed_at' => null,
        'deploy_age_seconds' => null,
        'queue' => ['pending' => 0, 'reserved' => 0, 'failed' => 0, 'oldest_pending_age_seconds' => null],
        'headline' => null,
    ];
}

// -------------------------------------- the instrument is WITHDRAWN --

it('exposes no way to hand it an app-authored shape', function (): void {
    // A regression guard on a REMOVAL. The withdrawn API was
    // `assertBuiltForCloudMetadataSchema(mixed, array $schema, string)`
    // plus a lexical walker advertised for "any metadata endpoint".
    // Neither exists, and the one public entry point takes a response
    // and a route NAME — there is no parameter through which a caller
    // supplies a shape.
    expect(method_exists($this, 'assertBuiltForCloudMetadataSchema'))->toBeFalse()
        ->and(method_exists($this, 'assertBuiltForCloudMetadataShape'))->toBeFalse()
        ->and(method_exists($this, 'builtForCloudMetadataSchemas'))->toBeFalse();

    $entry = new ReflectionMethod($this, 'assertBuiltForCloudMetadataEndpoint');

    expect($entry->getNumberOfParameters())->toBe(2);

    foreach ($entry->getParameters() as $parameter) {
        expect((string) $parameter->getType())->not->toContain('array');
    }
});

it('cannot be steered by a class that substitutes the withdrawn private methods', function (): void {
    // PHP trait precedence: a class using a trait may declare a method
    // with the same name as one of the trait's PRIVATE methods, and the
    // class's definition wins. While the registry and the evaluator were
    // trait privates, this consumer would have substituted both.
    $consumer = new SubstitutingContractConsumer;

    // Its registry names an app endpoint. It is not consulted, so the
    // route is still unknown.
    expect(fn () => $consumer->assertBuiltForCloudMetadataEndpoint(metadataResponse(['note' => 'pending']), 'GET /app/anything'))
        ->toThrow(AssertionFailedError::class);

    // Its permissive evaluator and its looser `ok` domain are not
    // consulted either: the package's own shape still applies.
    expect(fn () => $consumer->assertBuiltForCloudMetadataEndpoint(metadataResponse(['ok' => false]), 'POST /bfc/ownership/cancel-transfer'))
        ->toThrow(AssertionFailedError::class);

    $consumer->assertBuiltForCloudMetadataEndpoint(metadataResponse(['ok' => true]), 'POST /bfc/ownership/cancel-transfer');

    // Structurally: there is nothing left in the trait to substitute…
    $trait = new ReflectionClass(ContractAssertions::class);

    foreach ([
        'builtForCloudMetadataShapes',
        'builtForCloudVitalsShape',
        'assertBuiltForCloudMetadataAgainst',
        'assertBuiltForCloudMetadataObject',
        'assertBuiltForCloudMetadataList',
        'assertBuiltForCloudMetadataOneOf',
        'assertBuiltForCloudMetadataRange',
    ] as $gone) {
        expect($trait->hasMethod($gone))->toBeFalse($gone);
    }

    // …and the boundary they moved behind cannot be subclassed, so its
    // statics cannot be replaced either.
    $boundary = new ReflectionClass(MetadataEndpointShapes::class);

    expect($boundary->isFinal())->toBeTrue();

    foreach ($boundary->getMethods() as $method) {
        expect($method->isStatic())->toBeTrue($method->getName());
    }
});

it('refuses to certify anything it has not enumerated', function (): void {
    // "I do not know this route" is a refusal, and an app endpoint is
    // never a route this knows.
    foreach (['GET /bfc/not-a-route', 'GET /api/app/own-metadata-endpoint', ''] as $unknown) {
        expect(fn () => $this->assertBuiltForCloudMetadataEndpoint(metadataResponse(['ok' => true]), $unknown))
            ->toThrow(AssertionFailedError::class);
    }
});

it('enumerates exactly the metadata rows the contract classifies', function (): void {
    // The contract's classification table is the list; this asserts the
    // enumeration covers all of it and nothing else, so a future
    // metadata endpoint cannot be added to the doc with its shape
    // quietly going missing.
    preg_match_all(
        '/^\| `(GET|POST|PUT|PATCH|DELETE) (\S+)` \| `metadata` \|/m',
        (string) file_get_contents(__DIR__.'/../docs/http-contract.md'),
        $matches,
        PREG_SET_ORDER,
    );

    $documented = array_map(static fn (array $match): string => $match[1].' '.$match[2], $matches);
    sort($documented);

    $enumerated = $this->builtForCloudMetadataEndpoints();
    sort($enumerated);

    expect($documented)->not->toBeEmpty()->and($enumerated)->toBe($documented);
});

// --------------------------------------------------------------- AC5' --

it('fails on an unexpected key or an out-of-domain value', function (callable $mutate, string $why): void {
    $payload = $mutate(metadataVitalsBody());

    expect(fn () => $this->assertBuiltForCloudMetadataEndpoint(metadataResponse($payload), 'GET /bfc/console/vitals'))
        ->toThrow(AssertionFailedError::class, '', $why);
})->with([
    'an unknown key whose value looks like an identifier' => [
        fn (array $p): array => [...$p, 'note' => 'pending'], 'unknown key',
    ],
    'an unknown key carrying a name' => [
        fn (array $p): array => [...$p, 'customer_name' => 'alice'], 'unknown key',
    ],
    'an unknown key nested one level down' => [
        fn (array $p): array => [...$p, 'queue' => [...$p['queue'], 'oldest_job' => 'podcast']], 'unknown nested key',
    ],
    'a missing required key' => [
        function (array $p): array {
            unset($p['health']);

            return $p;
        }, 'missing key',
    ],
    'a bare root string' => [fn (array $p): string => 'ok', 'root type'],
    'a numeric string where a number belongs' => [
        fn (array $p): array => [...$p, 'deploy_age_seconds' => '123'], 'numeric string',
    ],
    'an empty array as the root' => [fn (array $p): array => [], 'missing every key'],
    'an arbitrary nested list' => [
        fn (array $p): array => [...$p, 'queue' => [['pending' => 1]]], 'list where an object belongs',
    ],
    'an enum member outside the vocabulary' => [
        fn (array $p): array => [...$p, 'health' => 'dgraded'], 'near-miss enum member',
    ],
    // The judge's residual: `down` is in the Health vocabulary for the
    // fleet dashboard and `Health::fromDegradation` cannot produce it,
    // so this endpoint's expected shape must not admit it either.
    'a health value the producer cannot emit' => [
        fn (array $p): array => [...$p, 'health' => 'down'], 'unreachable enum member',
    ],
    'a null where the shape forbids it' => [
        fn (array $p): array => [...$p, 'health' => null], 'non-nullable field',
    ],
    'an integer outside its range' => [
        fn (array $p): array => [...$p, 'queue' => [...$p['queue'], 'pending' => -1]], 'negative count',
    ],
    'a non-finite number' => [
        fn (array $p): array => [...$p, 'headline' => ['value' => INF, 'label' => 'active-sessions', 'unit' => null]],
        'non-finite float',
    ],
    'a semver carrying a person name' => [
        fn (array $p): array => [...$p, 'app_version' => '1.4.2+Jane.Operator'], 'semver escape',
    ],
    'a semver carrying a prose build tag' => [
        fn (array $p): array => [...$p, 'app_version' => '1.4.2-ReleaseCandidateTuesday'], 'semver escape',
    ],
    'an over-long semver' => [
        fn (array $p): array => [...$p, 'app_version' => str_repeat('1.2.3-', 12).'a'], 'unbounded length',
    ],
    'unicode free text where a label belongs' => [
        fn (array $p): array => [...$p, 'headline' => ['value' => 1, 'label' => 'niño feliz', 'unit' => null]],
        'unicode free text',
    ],
    'a cyrillic homoglyph label' => [
        fn (array $p): array => [...$p, 'headline' => ['value' => 1, 'label' => 'оk', 'unit' => null]],
        'homoglyph',
    ],
    'a wrong scalar type' => [
        fn (array $p): array => [...$p, 'version' => '1'], 'string where an int belongs',
    ],
]);

it('accepts the enumerated shape (the positive control)', function (): void {
    $this->assertBuiltForCloudMetadataEndpoint(metadataResponse(metadataVitalsBody()), 'GET /bfc/console/vitals');
});

it('takes its numeric bounds from the producer, at the boundary', function (): void {
    // Behavioural rather than structural: the shape is private, so this
    // proves the bound IS the producer's constant by driving both sides
    // of it. A bound written twice is a bound that will disagree with
    // itself, and this one already did.
    $atBound = [...metadataVitalsBody(), 'deploy_age_seconds' => VitalsPayload::MAX_AGE_SECONDS];
    $pastBound = [...metadataVitalsBody(), 'deploy_age_seconds' => VitalsPayload::MAX_AGE_SECONDS + 1];

    $this->assertBuiltForCloudMetadataEndpoint(metadataResponse($atBound), 'GET /bfc/console/vitals');

    expect(fn () => $this->assertBuiltForCloudMetadataEndpoint(metadataResponse($pastBound), 'GET /bfc/console/vitals'))
        ->toThrow(AssertionFailedError::class);

    // A headline label is only valid as a CASE of the app's declared
    // vocabulary, so the app has to declare one for these payloads to be
    // producible at all.
    app()->bind(CredentialDeclaration::class, HeadlineDeclaration::class);

    $headlineAt = [...metadataVitalsBody(), 'headline' => [
        'value' => VitalsPayload::MAX_HEADLINE_MAGNITUDE, 'label' => 'active-sessions', 'unit' => 'count',
    ]];
    $headlinePast = [...metadataVitalsBody(), 'headline' => [
        'value' => VitalsPayload::MAX_HEADLINE_MAGNITUDE * 10, 'label' => 'active-sessions', 'unit' => 'count',
    ]];

    $this->assertBuiltForCloudMetadataEndpoint(metadataResponse($headlineAt), 'GET /bfc/console/vitals');

    expect(fn () => $this->assertBuiltForCloudMetadataEndpoint(metadataResponse($headlinePast), 'GET /bfc/console/vitals'))
        ->toThrow(AssertionFailedError::class);
});

it('refuses domains wider than their producers', function (callable $mutate, string $endpoint): void {
    expect(fn () => $this->assertBuiltForCloudMetadataEndpoint(metadataResponse($mutate()), $endpoint))
        ->toThrow(AssertionFailedError::class);
})->with([
    // `ManageOwnership::cancelTransfer` can only emit `true`. Accepting
    // either boolean was a domain wider than the producer.
    'cancel-transfer ok: false' => [
        fn (): array => ['ok' => false], 'POST /bfc/ownership/cancel-transfer',
    ],
    // A version string that is a valid semver and is not THIS release.
    'a bfc_version that is not this release' => [
        fn (): array => [...metadataVitalsBody(), 'bfc_version' => '9.9.9'], 'GET /bfc/console/vitals',
    ],
]);

it('refuses an identifier-shaped headline label that is no member of the declared vocabulary', function (): void {
    // THE HOLE THE ENUM WORK EXISTED TO CLOSE, reopened one layer up:
    // the assertion accepted any token-shaped label, and
    // `customer-incident` is token-shaped while being a member of
    // nothing. Being identifier-shaped is not membership.
    app()->bind(CredentialDeclaration::class, HeadlineDeclaration::class);

    $outOfDomain = [...metadataVitalsBody(), 'headline' => [
        'value' => 3, 'label' => 'customer-incident', 'unit' => 'count',
    ]];

    expect(fn () => $this->assertBuiltForCloudMetadataEndpoint(metadataResponse($outOfDomain), 'GET /bfc/console/vitals'))
        ->toThrow(AssertionFailedError::class);

    // The positive control: a real case of the declared enum passes, so
    // the assertion above is not simply refusing every headline.
    $inDomain = [...metadataVitalsBody(), 'headline' => [
        'value' => 3, 'label' => SinkHeadlineLabel::OpenCases->value, 'unit' => 'count',
    ]];

    $this->assertBuiltForCloudMetadataEndpoint(metadataResponse($inDomain), 'GET /bfc/console/vitals');
});

it('refuses any headline at all when the app declares no vocabulary', function (): void {
    // The producer reports no headline in that case, so a payload
    // carrying one could not have come from it.
    $withHeadline = [...metadataVitalsBody(), 'headline' => [
        'value' => 3, 'label' => 'active-sessions', 'unit' => 'count',
    ]];

    expect(fn () => $this->assertBuiltForCloudMetadataEndpoint(metadataResponse($withHeadline), 'GET /bfc/console/vitals'))
        ->toThrow(AssertionFailedError::class);
});

it('derives the health and unit domains from the producer', function (): void {
    // Both are computed rather than restated, so a producer change
    // cannot leave the expected shape describing the old behaviour.
    // Driven at the members: every value the producer can construct
    // passes, and one it cannot does not.
    foreach ([false, true] as $degraded) {
        $this->assertBuiltForCloudMetadataEndpoint(
            metadataResponse([...metadataVitalsBody(), 'health' => Health::fromDegradation($degraded)->value]),
            'GET /bfc/console/vitals',
        );
    }

    expect(fn () => $this->assertBuiltForCloudMetadataEndpoint(
        metadataResponse([...metadataVitalsBody(), 'health' => Health::Down->value]),
        'GET /bfc/console/vitals',
    ))->toThrow(AssertionFailedError::class);

    app()->bind(CredentialDeclaration::class, HeadlineDeclaration::class);

    foreach (HeadlineUnit::cases() as $unit) {
        $this->assertBuiltForCloudMetadataEndpoint(
            metadataResponse([...metadataVitalsBody(), 'headline' => [
                'value' => 1, 'label' => 'active-sessions', 'unit' => $unit->value,
            ]]),
            'GET /bfc/console/vitals',
        );
    }

    expect(fn () => $this->assertBuiltForCloudMetadataEndpoint(
        metadataResponse([...metadataVitalsBody(), 'headline' => [
            'value' => 1, 'label' => 'active-sessions', 'unit' => 'furlongs',
        ]]),
        'GET /bfc/console/vitals',
    ))->toThrow(AssertionFailedError::class);
});

it('refuses a timestamp its producer would not have emitted', function (): void {
    // "An ISO-8601 instant" was wider than either producer: vitals emits
    // toAtomString(), re-key emits toRfc3339String(). A `Z` suffix
    // parses, is bounded, and is not what either one produces.
    foreach (['2026-08-29T09:14:00Z', '2026-08-29T09:14:00.500+00:00', '2026-08-29 09:14:00+00:00'] as $notEmitted) {
        expect(fn () => $this->assertBuiltForCloudMetadataEndpoint(
            metadataResponse([...metadataVitalsBody(), 'deployed_at' => $notEmitted]),
            'GET /bfc/console/vitals',
        ))->toThrow(AssertionFailedError::class, '', $notEmitted);
    }

    // The positive control: what the producer actually emits.
    $this->assertBuiltForCloudMetadataEndpoint(
        metadataResponse([...metadataVitalsBody(), 'deployed_at' => now()->toAtomString()]),
        'GET /bfc/console/vitals',
    );
});

it('rejects a body that is neither empty nor json', function (): void {
    $response = new TestResponse(new Response('not json at all', 200));

    expect(fn () => $this->assertBuiltForCloudMetadataEndpoint($response, 'POST /bfc/ownership/cancel-transfer'))
        ->toThrow(AssertionFailedError::class);
});

it('rejects a body where the shape requires an empty one', function (): void {
    expect(fn () => $this->assertBuiltForCloudMetadataEndpoint(metadataResponse(['leaked' => 'data']), 'DELETE /bfc/credentials/{id}'))
        ->toThrow(AssertionFailedError::class);
});

it('certifies both offboard shapes and refuses a hybrid of them', function (): void {
    $this->assertBuiltForCloudMetadataEndpoint(
        metadataResponse(['offboarded' => true, 'fully_contained' => true]),
        'POST /bfc/subjects/offboard',
    );
    $this->assertBuiltForCloudMetadataEndpoint(
        metadataResponse(['accepted' => true, 'fully_contained' => false]),
        'POST /bfc/subjects/offboard',
    );

    // Two documented shapes is a CHOICE between exact shapes, never a
    // union of their keys.
    foreach ([
        ['offboarded' => true, 'accepted' => true, 'fully_contained' => true],
        ['offboarded' => true],
        ['offboarded' => true, 'fully_contained' => true, 'note' => 'pending'],
        ['accepted' => false, 'fully_contained' => true],
    ] as $hybrid) {
        expect(fn () => $this->assertBuiltForCloudMetadataEndpoint(metadataResponse($hybrid), 'POST /bfc/subjects/offboard'))
            ->toThrow(AssertionFailedError::class);
    }
});

it('bounds list ITEMS and not list length', function (): void {
    // How many rows share a name is not a classification concern, and
    // the producer caps nothing — an earlier revision's 1,000 was a
    // bound written where nothing enforced it.
    $ids = array_map(static fn (int $i): string => 'id-'.$i, range(1, 1500));

    $this->assertBuiltForCloudMetadataEndpoint(metadataResponse(['revoked_ids' => $ids]), 'DELETE /api/credentials/{name}');

    expect(fn () => $this->assertBuiltForCloudMetadataEndpoint(
        metadataResponse(['revoked_ids' => ['ok', 'Jane Operator']]),
        'DELETE /api/credentials/{name}',
    ))->toThrow(AssertionFailedError::class);
});

it('keeps the console key id type pinned to the keyring own charset', function (): void {
    // One regex, never a second copy that could drift from it — the
    // promise ConsoleKeyring::isValidKeyId already makes.
    expect(MetadataShape::CONSOLE_KEY_ID)->toBe(ConsoleKeyring::KEY_ID_PATTERN);

    foreach (['K2.probe', 'k1', 'a-b_c.1', str_repeat('a', 64)] as $valid) {
        expect(MetadataShape::isConsoleKeyId($valid))->toBeTrue($valid)
            ->and(ConsoleKeyring::isValidKeyId($valid))->toBeTrue($valid);
    }

    foreach (['has space', '', str_repeat('a', 65), 'has/slash', "k1\nk2"] as $invalid) {
        expect(MetadataShape::isConsoleKeyId($invalid))->toBeFalse($invalid)
            ->and(ConsoleKeyring::isValidKeyId($invalid))->toBeFalse($invalid);
    }
});

// ------------------------------- driven against the live routes: AC4' --

it('holds the classification on the metadata-classified endpoints the package serves', function (): void {
    config([
        'auth.guards.bfc' => ['driver' => 'bfc', 'provider' => 'users'],
    ]);

    $this->assertBuiltForCloudMetadataEndpoint(
        $this->getJson('/bfc/console/vitals', [
            'Authorization' => metadataOperator(OperatorAbility::MetadataRead)->bearerHeader(),
        ])->assertOk(),
        'GET /bfc/console/vitals',
    );

    $this->assertBuiltForCloudMetadataEndpoint(
        $this->postJson('/bfc/ownership/cancel-transfer', [], [
            'Authorization' => 'Bearer '.metadataAdminToken(),
        ])->assertOk(),
        'POST /bfc/ownership/cancel-transfer',
    );

    // BOTH offboard shapes, through the real route.
    $this->assertBuiltForCloudMetadataEndpoint(
        $this->postJson('/bfc/subjects/offboard', [
            'subject_type' => SubjectType::ExternalConsumer->value,
            'subject_ref' => 'acme',
        ], ['Authorization' => metadataOperator(OperatorAbility::SubjectOffboard)->bearerHeader()])->assertOk(),
        'POST /bfc/subjects/offboard',
    );

    $this->assertBuiltForCloudMetadataEndpoint(
        $this->postJson('/bfc/subjects/offboard', [
            'subject_type' => SubjectType::ExternalConsumer->value,
            'subject_ref' => 'sponsor-login',
            'integration_namespace' => 'github-sponsors',
            'event_id' => 'evt-metadata-1',
            'entitlement_version' => 1,
            'external_subject' => 'sponsor-login',
        ], ['Authorization' => metadataOperator(OperatorAbility::SubjectOffboard)->bearerHeader()])
            ->assertStatus(202),
        'POST /bfc/subjects/offboard',
    );

    $target = $this->mintCredential(['subject_ref' => 'revoke-target']);

    $this->assertBuiltForCloudMetadataEndpoint(
        $this->deleteJson('/bfc/credentials/'.$target->credential->id, [], [
            'Authorization' => metadataOperator(OperatorAbility::CredentialRevoke)->bearerHeader(),
        ])->assertNoContent(),
        'DELETE /bfc/credentials/{id}',
    );
});

it('holds the classification on the console key-custody row', function (): void {
    OwnershipClaim::query()->create(['token_hash' => OwnershipClaim::hashToken('metadata-owner')]);
    $this->postJson('/bfc/ownership/claim', ['token' => 'metadata-owner'])->assertCreated();

    // The key id deliberately carries a capital: `kid`s are bounded in
    // `[A-Za-z0-9._-]{1,64}`, which is a charset of their own.
    $filed = $this->postJson('/bfc/console/re-key', [
        'key_id' => 'K2.metadata-probe',
        'public_key' => consoleKeypair()->getPublicKey()->toHexString(),
    ], ['Authorization' => metadataOperator(OperatorAbility::ConsoleKeyWrite)->bearerHeader()])
        ->assertCreated();

    $this->assertBuiltForCloudMetadataEndpoint($filed, 'POST /bfc/console/re-key');
});

it('holds the classification on the console key-retirement row', function (): void {
    OwnershipClaim::query()->create(['token_hash' => OwnershipClaim::hashToken('metadata-retire-owner')]);
    $this->postJson('/bfc/ownership/claim', ['token' => 'metadata-retire-owner'])->assertCreated();

    $writer = metadataOperator(OperatorAbility::ConsoleKeyWrite);

    // Two keys, so the retirement below is not the last-active-key case
    // and answers its ordinary success shape. The capital is deliberate:
    // a `kid` is bounded in `[A-Za-z0-9._-]`, a charset of its own.
    foreach (['K1.metadata-outgoing', 'K2.metadata-incoming'] as $keyId) {
        $this->postJson('/bfc/console/re-key', [
            'key_id' => $keyId,
            'public_key' => consoleKeypair()->getPublicKey()->toHexString(),
        ], ['Authorization' => $writer->bearerHeader()])->assertCreated();
    }

    $this->assertBuiltForCloudMetadataEndpoint(
        $this->postJson('/bfc/console/keys/K1.metadata-outgoing/retire', [], [
            'Authorization' => $writer->bearerHeader(),
        ])->assertOk(),
        'POST /bfc/console/keys/{key_id}/retire',
    );
});

it('holds the classification on the personal-surface row', function (): void {
    config(['built-for-cloud.credentials.declaration' => SelfServiceDeclaration::class]);

    /** @var User $user */
    $user = User::query()->create([
        'name' => 'metadata@example.test',
        'email' => 'metadata@example.test',
        'password' => bcrypt('secret-'.bin2hex(random_bytes(4))),
    ]);

    $credential = Credential::query()->create([
        'kind' => CredentialKind::Bearer,
        'subject_type' => SubjectType::UserPrincipal,
        'subject_ref' => 'user:'.$user->getAuthIdentifier(),
        'user_id' => (string) $user->getAuthIdentifier(),
        'name' => 'laptop',
        'status' => CredentialStatus::Active,
        'secret_hash' => hash('sha256', 'seeded-'.bin2hex(random_bytes(8))),
    ]);

    $this->assertBuiltForCloudMetadataEndpoint(
        $this->actingAs($user)->deleteJson('/bfc/me/credentials/'.$credential->id)->assertNoContent(),
        'DELETE /bfc/me/credentials/{id}',
    );
});
