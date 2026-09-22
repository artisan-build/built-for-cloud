<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\Exceptions\ManagedAuthRefused;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\ManagedAuthClient;
use ArtisanBuild\BuiltForCloud\ManagedAuthConnection;
use ArtisanBuild\BuiltForCloud\ManagedTransition;
use ArtisanBuild\BuiltForCloud\ManagedTransitionDirection;
use ArtisanBuild\BuiltForCloud\ManagedTransitions;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\ManagedAuthorityFixture;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\ManagedTransitionAuthorityFixture;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

final class ManagedOutboundContractDocTest extends TestCase
{
    use RefreshDatabase;

    public function test_managed_auth_documented_shapes_match_the_client_and_authority_fixture(): void
    {
        $baseUrl = 'https://'.strtolower(Str::random(12)).'.example.test';
        $secret = bin2hex(random_bytes(32));
        $issuer = 'https://issuer-'.strtolower(Str::random(12)).'.example.test';
        $connectionId = (string) Str::uuid();
        $organizationId = (string) Str::uuid();
        $installationId = (string) Str::uuid();
        $generation = random_int(10, 100);
        $fixture = new ManagedAuthorityFixture(
            $baseUrl,
            $secret,
            $issuer,
            $connectionId,
            $organizationId,
            $installationId,
            $generation,
        );
        $responses = [];
        $fixture->handoffTransform = static function (array $payload) use (&$responses): array {
            $responses['handoff'] = $payload;

            return $payload;
        };
        $fixture->exchangeTransform = static function (array $payload) use (&$responses): array {
            unset($payload['_request_id_observed']);
            $responses['exchange'] = $payload;

            return $payload;
        };
        $fixture->confirmationResponder = static function (array $request, array $payload) use (&$responses) {
            $responses['confirm'] = $payload;

            return Http::response($payload);
        };
        $fixture->ownershipResponder = static function (array $request, array $payload) use (&$responses) {
            $responses['ownership'] = $payload;

            return Http::response($payload);
        };
        Http::fake(static fn (Request $request): mixed => $fixture->respond($request));

        $connection = new ManagedAuthConnection(
            $issuer,
            $connectionId,
            $organizationId,
            $installationId,
            $generation,
            $baseUrl,
            $secret,
            null,
        );
        $requestId = $this->opaqueKey();
        $code = 'code-'.Str::random(24);
        $subjectId = 'subject-'.Str::random(20);
        $seatedOwnerId = 'owner-'.Str::random(20);
        $user = new User;
        $user->forceFill([
            'scalpels_id' => $subjectId,
            'managed_membership_roster_version' => random_int(100, 200),
            'managed_membership_response_sequence' => random_int(300, 400),
            'managed_membership_responded_at' => '2026-09-22T12:34:56+00:00',
        ]);
        $client = app(ManagedAuthClient::class);

        $client->createHandoff($connection, $requestId);
        $client->exchange($connection, $requestId, $code);
        $client->confirm($connection, $user);
        $client->ownership($connection, $seatedOwnerId);

        $contracts = [
            ['handoff', 'POST /managed-auth/v1/handoffs', $fixture->calls[0]],
            ['exchange', 'POST /managed-auth/v1/handoffs/{request_id}/exchange', $fixture->calls[1]],
            ['confirm', 'POST /managed-auth/v1/memberships/confirm', $fixture->calls[2]],
            ['ownership', 'POST /managed-transition/v1/ownership', $fixture->calls[3]],
        ];

        foreach ($contracts as [$leg, $endpoint, $call]) {
            $this->assertSame('POST', $call['method']);
            $this->assertSame(
                $this->documentedFields($endpoint, 'Request fields'),
                array_keys($call['body']),
                "{$endpoint} request fields drifted from docs/managed-outbound-contract.md.",
            );
            $this->assertSame(
                $this->documentedFields($endpoint, 'Response fields'),
                array_keys($responses[$leg]),
                "{$endpoint} response fields drifted from docs/managed-outbound-contract.md.",
            );
        }

        $this->assertSame($requestId, $fixture->calls[0]['body']['request_id']);
        $this->assertSame($code, $fixture->calls[1]['body']['code']);
        $this->assertSame($subjectId, $fixture->calls[2]['body']['scalpels_id']);
        $this->assertSame($seatedOwnerId, $fixture->calls[3]['body']['seated_owner_scalpels_id']);

        foreach (['exchange', 'confirm', 'ownership'] as $leg) {
            $this->assertSame($issuer, $responses[$leg]['issuer']);
            $this->assertSame($connectionId, $responses[$leg]['connection_id']);
            $this->assertSame($organizationId, $responses[$leg]['organization_id']);
            $this->assertSame($installationId, $responses[$leg]['installation_id']);
            $this->assertSame($generation, $responses[$leg]['authority_generation']);
        }

        $this->assertSame(
            $this->documentedFields('POST /managed-transition/v1/ownership', 'Owner subject fields'),
            array_keys($responses['ownership']['owner']),
        );
        $this->assertSame($seatedOwnerId, $responses['ownership']['seated_owner']['scalpels_id']);
    }

    public function test_managed_transition_documented_shapes_match_the_client_and_authority_fixture(): void
    {
        $baseUrl = 'https://'.strtolower(Str::random(12)).'.example.test';
        $secret = bin2hex(random_bytes(32));
        $issuer = 'https://issuer-'.strtolower(Str::random(12)).'.example.test';
        $connectionId = (string) Str::uuid();
        $organizationId = (string) Str::uuid();
        $installationId = (string) Str::uuid();
        $generation = random_int(10, 100);

        DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
            'mode' => AuthorityMode::Standalone->value,
            'generation' => $generation,
            'issuer' => $issuer,
            'connection_id' => $connectionId,
            'organization_id' => $organizationId,
            'installation_id' => $installationId,
            'authority_base_url' => $baseUrl,
        ]);
        config([
            'built-for-cloud.managed.client_secret' => $secret,
            'built-for-cloud.managed.ca_bundle' => null,
        ]);
        $owner = User::query()->create([
            'name' => 'Owner '.Str::random(12),
            'email' => strtolower(Str::random(12)).'@example.test',
        ]);
        $owner->forceFill(['role' => 'owner', 'status' => 'active'])->save();

        $fixture = new ManagedTransitionAuthorityFixture(
            baseUrl: $baseUrl,
            clientSecret: $secret,
            issuer: $issuer,
            connectionId: $connectionId,
            organizationId: $organizationId,
            installationId: $installationId,
            generation: $generation,
        );
        $responses = [];
        $fixture->transform = static function (string $leg, array $payload) use (&$responses): array {
            $responses[$leg] = $payload;

            return $payload;
        };
        Http::fake(static fn (Request $request): mixed => $fixture->respond($request));
        $transitions = app(ManagedTransitions::class);

        $fixture->crashAfterExecution = 'T1';
        try {
            $transitions->prepare($owner, ManagedTransitionDirection::Adopt);
            $this->fail('The outcome-unknown prepare fixture did not interrupt T1.');
        } catch (ManagedAuthRefused) {
            // The durable preparing row is the input to T6 recovery.
        }

        $recovered = $transitions->recover(ManagedTransition::query()->sole());
        $transitions->abandonPreCommit($owner->refresh(), $recovered);

        $transition = $transitions->prepare($owner->refresh(), ManagedTransitionDirection::Adopt);
        $transition = $transitions->fetchRoster($transition);
        $transition = $transitions->propose($transition, [
            [
                'scalpels_id' => 'direct-member',
                'local_kind' => null,
                'local_id' => null,
                'role' => 'member',
                'disposition' => 'create',
                'final_email' => strtolower(Str::random(12)).'@example.test',
            ],
            [
                'scalpels_id' => null,
                'local_kind' => 'user',
                'local_id' => (string) $owner->getKey(),
                'role' => null,
                'disposition' => 'exclude',
                'final_email' => null,
            ],
        ]);
        $transition = $transitions->stage($transition);
        $transition = $transitions->commit($transition, $owner->refresh());
        $transitions->acknowledge($transition);

        $endpoints = [
            'T1' => 'POST /managed-transition/v1/transitions',
            'T2' => 'POST /managed-transition/v1/transitions/{transition_id}/roster',
            'T3' => 'POST /managed-transition/v1/transitions/{transition_id}/stage',
            'T4' => 'POST /managed-transition/v1/transitions/{transition_id}/ack',
            'T5' => 'POST /managed-transition/v1/transitions/{transition_id}',
            'T6' => 'POST /managed-transition/v1/transition-requests/{transition_request_id}',
            'T7' => 'POST /managed-transition/v1/transitions/{transition_id}/abandon',
        ];

        foreach ($fixture->calls as $call) {
            $body = json_decode($call['body'], true, flags: JSON_THROW_ON_ERROR);
            $endpoint = $endpoints[$call['leg']];
            $this->assertSame(
                $this->documentedFields($endpoint, 'Request fields'),
                array_keys($body),
                "{$endpoint} request fields drifted from docs/managed-outbound-contract.md.",
            );
            $this->assertSame($connectionId, $body['connection_id']);
            $this->assertSame($installationId, $body['installation_id']);

            if (in_array($call['leg'], ['T1', 'T3', 'T4', 'T7'], true)) {
                $this->assertSame(hash('sha256', $call['body']), $call['digest']);
            } else {
                $this->assertNull($call['digest']);
            }
        }

        foreach ($endpoints as $leg => $endpoint) {
            $this->assertArrayHasKey($leg, $responses, "The fixture never produced a {$leg} response.");
            $this->assertSame(
                $this->documentedFields($endpoint, 'Response fields'),
                array_keys($responses[$leg]),
                "{$endpoint} response fields drifted from docs/managed-outbound-contract.md.",
            );
            $this->assertSame($issuer, $responses[$leg]['issuer']);
            $this->assertSame($connectionId, $responses[$leg]['connection_id']);
            $this->assertSame($organizationId, $responses[$leg]['organization_id']);
            $this->assertSame($installationId, $responses[$leg]['installation_id']);
            $this->assertSame($leg === 'T4' ? $generation + 1 : $generation, $responses[$leg]['authority_generation']);
        }

        $rosterCall = collect($fixture->calls)->firstWhere('leg', 'T2');
        $stageCall = collect($fixture->calls)->firstWhere('leg', 'T3');
        $ackCall = collect($fixture->calls)->firstWhere('leg', 'T4');
        $recoveryCall = collect($fixture->calls)->firstWhere('leg', 'T6');
        $rosterBody = json_decode($rosterCall['body'], true, flags: JSON_THROW_ON_ERROR);
        $stageBody = json_decode($stageCall['body'], true, flags: JSON_THROW_ON_ERROR);
        $ackBody = json_decode($ackCall['body'], true, flags: JSON_THROW_ON_ERROR);

        $this->assertSame($responses['T1']['roster_version'], $rosterBody['roster_version']);
        $this->assertSame($responses['T1']['roster_cutoff_at'], $rosterBody['roster_cutoff_at']);
        $this->assertSame($responses['T1']['roster_version'], $stageBody['roster_version']);
        $this->assertSame($responses['T1']['roster_cutoff_at'], $stageBody['roster_cutoff_at']);
        $this->assertSame($generation + 1, $ackBody['generation_after']);
        $this->assertSame($ackBody['local_commit_receipt'], $responses['T4']['local_commit_receipt']);
        $this->assertStringEndsWith(
            '/'.rawurlencode($responses['T6']['transition_request_id']),
            $recoveryCall['path'],
        );
        $this->assertSame(
            $this->documentedFields(
                'POST /managed-transition/v1/transitions/{transition_id}/roster',
                'Roster member fields',
            ),
            array_keys($responses['T2']['members'][0]),
        );
        $this->assertSame(
            $this->documentedFields(
                'POST /managed-transition/v1/transitions/{transition_id}/stage',
                'Mapping fields',
            ),
            array_keys($stageBody['mapping'][0]),
        );
    }

    /** @return list<string> */
    private function documentedFields(string $endpoint, string $table): array
    {
        $document = file_get_contents(dirname(__DIR__).'/docs/managed-outbound-contract.md');
        $this->assertIsString($document);
        $matched = preg_match(
            '/^### '.preg_quote($endpoint, '/').'\R(.*?)(?=^### |\z)/ms',
            $document,
            $endpointMatch,
        );
        $this->assertSame(1, $matched, "The outbound contract has no {$endpoint} section.");

        $matched = preg_match(
            '/^#### '.preg_quote($table, '/').'\R(.*?)(?=^#### |\z)/ms',
            $endpointMatch[1],
            $tableMatch,
        );
        $this->assertSame(1, $matched, "The {$endpoint} section has no {$table} table.");

        preg_match_all('/^\| `([^`]+)` \|/m', $tableMatch[1], $fieldMatches);
        $this->assertNotEmpty($fieldMatches[1], "The {$endpoint} {$table} table has no fields.");

        return $fieldMatches[1];
    }

    private function opaqueKey(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }
}
