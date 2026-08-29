<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\ContractAssertions;
use ArtisanBuild\BuiltForCloud\Testing\MintedTestCredential;
use ArtisanBuild\BuiltForCloud\Testing\WithCredentials;
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
 * Two halves, and the second is the one that matters: the assertion is
 * pointed at every `metadata`-classified endpoint the package serves, AND
 * it is driven to FAIL. An assertion that cannot fail is worse than none
 * — it reports a property nobody is holding.
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

// ----------------------------------------------------------- it fails --

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
]);

it('accepts the bounded forms a metadata endpoint may return', function (mixed $payload): void {
    $this->assertBuiltForCloudMetadataShape($payload, 'probe');
})->with([
    'enum members' => [['health' => 'degraded', 'unit' => 'seconds']],
    'an ability name' => [['ability' => 'metadata:read']],
    'a capability name' => [['capability' => 'console-vitals']],
    'a uuid' => [['id' => '0199e4a7-3d0a-7a44-9a2f-6c1f2a6b8d31']],
    'a semver with a pre-release' => [['version' => '1.4.2-beta.1']],
    'an ISO-8601 instant' => [['at' => '2026-08-29T09:14:00+00:00']],
    'a Z instant' => [['at' => '2026-08-29T09:14:00Z']],
    'numbers, booleans and nulls' => [['n' => 12, 'f' => 1.5, 'b' => true, 'nothing' => null]],
]);

// --------------------------------- pointed at the live metadata rows --

it('holds the classification on the metadata-classified endpoints the package serves', function (): void {
    config(['auth.guards.bfc' => ['driver' => 'bfc', 'provider' => 'users']]);

    // GET /bfc/console/vitals
    $vitals = $this->getJson('/bfc/console/vitals', [
        'Authorization' => metadataOperator(OperatorAbility::MetadataRead)->bearerHeader(),
    ])->assertOk();

    $this->assertBuiltForCloudMetadataResponse($vitals, 'GET /bfc/console/vitals');

    // POST /bfc/ownership/cancel-transfer
    $cancel = $this->postJson('/bfc/ownership/cancel-transfer', [], [
        'Authorization' => 'Bearer '.metadataAdminToken(),
    ])->assertOk();

    $this->assertBuiltForCloudMetadataResponse($cancel, 'POST /bfc/ownership/cancel-transfer');

    // POST /bfc/subjects/offboard
    $offboard = $this->postJson('/bfc/subjects/offboard', [
        'subject_type' => SubjectType::ExternalConsumer->value,
        'subject_ref' => 'acme',
    ], ['Authorization' => metadataOperator(OperatorAbility::SubjectOffboard)->bearerHeader()])->assertOk();

    $this->assertBuiltForCloudMetadataResponse($offboard, 'POST /bfc/subjects/offboard');

    // DELETE /bfc/credentials/{id} — an empty 204 body, which passes
    // trivially and is asserted anyway so the row is covered rather than
    // assumed.
    $target = $this->mintCredential(['subject_ref' => 'revoke-target']);

    $revoke = $this->deleteJson('/bfc/credentials/'.$target->credential->id, [], [
        'Authorization' => metadataOperator(OperatorAbility::CredentialRevoke)->bearerHeader(),
    ])->assertNoContent();

    $this->assertBuiltForCloudMetadataResponse($revoke, 'DELETE /bfc/credentials/{id}');
});

it('rejects a body that is neither empty nor json on a metadata endpoint', function (): void {
    $response = new TestResponse(
        new Response('not json at all', 200),
    );

    expect(fn () => $this->assertBuiltForCloudMetadataResponse($response, 'probe'))
        ->toThrow(AssertionFailedError::class);
});
