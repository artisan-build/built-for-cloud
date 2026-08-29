<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyring;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\MetadataShape;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\OwnershipClaim;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\ContractAssertions;
use ArtisanBuild\BuiltForCloud\Testing\MintedTestCredential;
use ArtisanBuild\BuiltForCloud\Testing\WithCredentials;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\SelfServiceDeclaration;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\User;
use ArtisanBuild\BuiltForCloud\Vitals\VitalsPayload;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Response;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\AssertionFailedError;

uses(RefreshDatabase::class, WithCredentials::class, ContractAssertions::class);

/**
 * Console PRD D15 / docs/http-contract.md "Endpoint classification" — the
 * conformance instrument, and the §7 acceptance row "the contract
 * conformance suite rejects a free-text field on any metadata-classified
 * endpoint".
 *
 * Three halves, and the middle one is the one that matters:
 *
 *  1. The FAIL-CLOSED schema check is driven to reject the shapes the
 *     earlier lexical-only revision passed: an unknown key whose value
 *     happens to look identifier-shaped, a numeric string, a bare root
 *     scalar, an empty array, an arbitrary nested list, a wrong enum
 *     member, an out-of-range number, a non-finite float, and a route
 *     with no shipped schema at all.
 *  2. The supplemental lexical walker is driven to FAIL on free text —
 *     including the semver escape the judge found, where
 *     `1.4.2+Jane.Operator` is valid semver carrying a person's name.
 *  3. Both are pointed at every `metadata`-classified endpoint the
 *     package serves.
 *
 * An assertion that cannot fail is worse than none, so every claim about
 * what this instrument rejects is a driven test rather than a docblock.
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
 * A payload that satisfies the shipped vitals schema, as the base for
 * the mutations below — so each rejection test differs from a PASSING
 * payload in exactly one way.
 *
 * @return array<string, mixed>
 */
function metadataVitalsBody(): array
{
    return [
        'version' => 1,
        'api_version' => 2,
        'bfc_version' => '0.5.0',
        'app_version' => null,
        'health' => 'ok',
        'deployed_at' => null,
        'deploy_age_seconds' => null,
        'queue' => ['pending' => 0, 'reserved' => 0, 'failed' => 0, 'oldest_pending_age_seconds' => null],
        'headline' => null,
    ];
}

// ------------------------------------------------- the schema closes --

it('accepts a payload that matches the shipped vitals schema (the positive control)', function (): void {
    $this->assertBuiltForCloudMetadataSchema(metadataVitalsBody(), $this->metadataVitalsSchema(), 'probe');
});

it('rejects a shape the schema does not recognise', function (callable $mutate, string $why): void {
    $payload = $mutate(metadataVitalsBody());

    expect(fn () => $this->assertBuiltForCloudMetadataSchema($payload, $this->metadataVitalsSchema(), 'probe'))
        ->toThrow(AssertionFailedError::class, '', $why);
})->with([
    // The exact fail-open cases the lexical-only revision passed: the
    // VALUE looks identifier-shaped, so nothing lexical could object.
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
    'a null where the schema forbids it' => [
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
    'a wrong scalar type' => [
        fn (array $p): array => [...$p, 'version' => '1'], 'string where an int belongs',
    ],
]);

it('refuses to certify a route it ships no schema for', function (): void {
    $response = new TestResponse(new Response('{"ok":true}', 200));

    expect(fn () => $this->assertBuiltForCloudMetadataEndpoint($response, 'GET /bfc/not-a-route'))
        ->toThrow(AssertionFailedError::class);
});

it('rejects a body that is neither empty nor json on a metadata endpoint', function (): void {
    $response = new TestResponse(new Response('not json at all', 200));

    expect(fn () => $this->assertBuiltForCloudMetadataEndpoint($response, 'POST /bfc/ownership/cancel-transfer'))
        ->toThrow(AssertionFailedError::class);
});

it('rejects a body where the schema requires an empty one', function (): void {
    $response = new TestResponse(new Response('{"leaked":"data"}', 200));

    expect(fn () => $this->assertBuiltForCloudMetadataEndpoint($response, 'DELETE /bfc/credentials/{id}'))
        ->toThrow(AssertionFailedError::class);
});

// ------------------------------------------- no app-supplied regexes --

it('refuses a schema that tries to supply its own pattern', function (): void {
    // THE THIRD FAIL-OPEN BRANCH, closed at the language level rather
    // than patched. `'type' => 'pattern'` with `/^.*$/sD` certified
    // `{"note": "arbitrary free text"}` and marked the path certified,
    // which also silenced the supplemental lexical check. A schema
    // author is the party being checked; they may not define what
    // "bounded" means.
    $schema = [
        'type' => 'object',
        'fields' => ['note' => ['type' => 'pattern', 'pattern' => '/^.*$/sD']],
    ];

    expect(fn () => $this->assertBuiltForCloudMetadataSchema(['note' => 'arbitrary free text'], $schema, 'probe'))
        ->toThrow(AssertionFailedError::class);

    // And the same escape attempted through a list item.
    $listSchema = [
        'type' => 'object',
        'fields' => ['tags' => ['type' => 'list', 'of' => ['type' => 'pattern', 'pattern' => '/.*/']]],
    ];

    expect(fn () => $this->assertBuiltForCloudMetadataSchema(['tags' => ['Jane Operator']], $listSchema, 'probe'))
        ->toThrow(AssertionFailedError::class);
});

it('names every string type it will certify, and refuses the rest', function (): void {
    // The set is CLOSED and package-owned. A schema naming a type this
    // package does not define is a refusal, not a pass — which is what
    // makes "an unrecognised shape fails" true of the type system too,
    // not just of the payload.
    foreach (['token', 'semver', 'timestamp', 'console_key_id'] as $type) {
        $this->assertBuiltForCloudMetadataSchema(
            ['field' => match ($type) {
                'token' => 'console-vitals',
                'semver' => '1.4.2-beta.1',
                'timestamp' => '2026-08-29T09:14:00+00:00',
                default => 'K2.probe',
            }],
            ['type' => 'object', 'fields' => ['field' => ['type' => $type]]],
            'probe',
        );
    }

    foreach (['pattern', 'regex', 'string', 'anything'] as $unknown) {
        expect(fn () => $this->assertBuiltForCloudMetadataSchema(
            ['field' => 'ok'],
            ['type' => 'object', 'fields' => ['field' => ['type' => $unknown]]],
            'probe',
        ))->toThrow(AssertionFailedError::class);
    }
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

// ------------------------------- the registry agrees with the routes --

it('reads its numeric bounds from the producer rather than restating them', function (): void {
    // A bound written twice is a bound that will disagree with itself,
    // and this one already did: the schema capped ages at ten years the
    // producer computed without limit, and rejected headline magnitudes
    // it was happy to emit.
    $schema = $this->metadataVitalsSchema();

    $headline = $schema['fields']['headline']['fields']['value'];
    $deployAge = $schema['fields']['deploy_age_seconds'];
    $queueAge = $schema['fields']['queue']['fields']['oldest_pending_age_seconds'];

    expect($headline['max'])->toBe(VitalsPayload::MAX_HEADLINE_MAGNITUDE)
        ->and($headline['min'])->toBe(-VitalsPayload::MAX_HEADLINE_MAGNITUDE)
        ->and($deployAge['max'])->toBe(VitalsPayload::MAX_AGE_SECONDS)
        ->and($deployAge['min'])->toBe(-VitalsPayload::MAX_AGE_SECONDS)
        ->and($queueAge['max'])->toBe(VitalsPayload::MAX_AGE_SECONDS)
        ->and($queueAge['min'])->toBe(-VitalsPayload::MAX_AGE_SECONDS);
});

it('bounds list ITEMS and not list length', function (): void {
    // How many rows share a name is not a classification concern, and
    // the producer caps nothing — the schema's old 1,000 was a bound
    // written where nothing enforced it.
    $ids = array_map(static fn (int $i): string => 'id-'.$i, range(1, 1500));

    $this->assertBuiltForCloudMetadataSchema(
        ['revoked_ids' => $ids],
        $this->builtForCloudMetadataSchemas()['DELETE /api/credentials/{name}'],
        'probe',
    );

    // Each ITEM is still bounded, which is the claim actually made.
    expect(fn () => $this->assertBuiltForCloudMetadataSchema(
        ['revoked_ids' => ['ok', 'Jane Operator']],
        $this->builtForCloudMetadataSchemas()['DELETE /api/credentials/{name}'],
        'probe',
    ))->toThrow(AssertionFailedError::class);
});

it('certifies both offboard shapes and refuses a hybrid of them', function (): void {
    $schema = $this->builtForCloudMetadataSchemas()['POST /bfc/subjects/offboard'];

    $this->assertBuiltForCloudMetadataSchema(['offboarded' => true, 'fully_contained' => true], $schema, 'direct');
    $this->assertBuiltForCloudMetadataSchema(['accepted' => true, 'fully_contained' => false], $schema, 'integration');

    // `one_of` is a choice between EXACT shapes, not a union of their
    // keys — otherwise fail-closed would have been traded away for the
    // second shape.
    foreach ([
        ['offboarded' => true, 'accepted' => true, 'fully_contained' => true],
        ['offboarded' => true],
        ['offboarded' => true, 'fully_contained' => true, 'note' => 'pending'],
        ['accepted' => false, 'fully_contained' => true],
    ] as $hybrid) {
        expect(fn () => $this->assertBuiltForCloudMetadataSchema($hybrid, $schema, 'probe'))
            ->toThrow(AssertionFailedError::class);
    }
});

// ------------------------------------ the lexical walker still bites --

it('rejects a free-text field on a metadata payload', function (mixed $payload): void {
    expect(fn () => $this->assertBuiltForCloudMetadataShape($payload, 'probe'))
        ->toThrow(AssertionFailedError::class);
})->with([
    'a sentence' => [['note' => 'the queue is backed up']],
    'a display name' => [['label' => 'Jane Operator']],
    'a capitalised word' => [['product' => 'Laravel']],
    'an email address' => [['recipient' => 'ops@example.com']],
    'a path' => [['path' => '/var/log/app.log']],
    'an empty string' => [['name' => '']],
    'an over-long identifier' => [['id' => str_repeat('a', 65)]],
    'nested one level down' => [[['queue' => ['oldest_job' => 'ProcessPodcast job, queued Tuesday']]]],
    'inside a list' => [['tags' => ['ok', 'a free text tag']]],
    'a free-text KEY' => [['Jane Operator' => 1]],
    'a bare free-text string' => ['the whole body is prose'],
    'an object the walker cannot bound' => [['at' => new stdClass]],
    // AC15. Every one of these passed the earlier revision.
    'a semver carrying a person name' => [['app_version' => '1.4.2+Jane.Operator']],
    'a semver carrying a prose build tag' => [['app_version' => '1.4.2-ReleaseCandidateTuesday']],
    'an over-long semver' => [['app_version' => str_repeat('1.2.3-', 12).'a']],
    'a non-finite float' => [['value' => NAN]],
    'unicode free text' => [['label' => 'niño feliz']],
    'a single unicode word' => [['label' => '本番環境']],
    'a cyrillic homoglyph identifier' => [['label' => 'оk']],
]);

it('accepts the bounded forms a metadata endpoint may return', function (mixed $payload): void {
    $this->assertBuiltForCloudMetadataShape($payload, 'probe');
})->with([
    'enum members' => [['health' => 'degraded', 'unit' => 'seconds']],
    'an ability name' => [['ability' => 'metadata:read']],
    'a capability name' => [['capability' => 'console-vitals']],
    'a uuid' => [['id' => '0199e4a7-3d0a-7a44-9a2f-6c1f2a6b8d31']],
    'a semver with a lowercase pre-release' => [['version' => '1.4.2-beta.1']],
    'an ISO-8601 instant' => [['at' => '2026-08-29T09:14:00+00:00']],
    'a Z instant' => [['at' => '2026-08-29T09:14:00Z']],
    'numbers, booleans and nulls' => [['n' => 12, 'f' => 1.5, 'b' => true, 'nothing' => null]],
]);

// --------------------------------- pointed at the live metadata rows --

it('holds the classification on the metadata-classified endpoints the package serves', function (): void {
    config(['auth.guards.bfc' => ['driver' => 'bfc', 'provider' => 'users']]);

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

    // BOTH offboard shapes, through the real route. The registry used to
    // admit only the direct one while its own comment acknowledged the
    // other — a registry disagreeing with the route it certifies.
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
    // The re-key verb needs a deployment that has already claimed.
    OwnershipClaim::query()->create(['token_hash' => OwnershipClaim::hashToken('metadata-owner')]);
    $this->postJson('/bfc/ownership/claim', ['token' => 'metadata-owner'])->assertCreated();

    $filed = $this->postJson('/bfc/console/re-key', [
        'key_id' => 'K2.metadata-probe',
        'public_key' => consoleKeypair()->getPublicKey()->toHexString(),
    ], ['Authorization' => metadataOperator(OperatorAbility::ConsoleKeyWrite)->bearerHeader()])
        ->assertCreated();

    // The key id deliberately carries a capital: `kid`s are bounded in
    // `[A-Za-z0-9._-]{1,64}`, which is NOT the lowercase token
    // vocabulary, so this row is the one that proves the schema — and
    // not the lexical walker — is the authority on a pinned field.
    $this->assertBuiltForCloudMetadataEndpoint($filed, 'POST /bfc/console/re-key');
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

it('ships a schema for every metadata row the contract classifies', function (): void {
    // The contract's classification table is the list; this asserts the
    // instrument covers all of it, so a future metadata endpoint cannot
    // be added to the doc without a schema quietly going missing.
    $documented = [];

    preg_match_all(
        '/^\| `(GET|POST|PUT|PATCH|DELETE) (\S+)` \| `metadata` \|/m',
        (string) file_get_contents(__DIR__.'/../docs/http-contract.md'),
        $matches,
        PREG_SET_ORDER,
    );

    foreach ($matches as $match) {
        $documented[] = $match[1].' '.$match[2];
    }

    sort($documented);

    $shipped = array_keys($this->builtForCloudMetadataSchemas());
    sort($shipped);

    expect($documented)->not->toBeEmpty()
        ->and(array_values(array_diff($documented, $shipped)))->toBe([])
        ->and(array_values(array_diff($shipped, $documented)))->toBe([]);
});
