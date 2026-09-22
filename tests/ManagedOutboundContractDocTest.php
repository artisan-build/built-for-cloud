<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\Exceptions\ManagedAuthRefused;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\Invitation;
use ArtisanBuild\BuiltForCloud\ManagedAuthClient;
use ArtisanBuild\BuiltForCloud\ManagedAuthConnection;
use ArtisanBuild\BuiltForCloud\ManagedTransition;
use ArtisanBuild\BuiltForCloud\ManagedTransitionClient;
use ArtisanBuild\BuiltForCloud\ManagedTransitionDirection;
use ArtisanBuild\BuiltForCloud\ManagedTransitions;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\ManagedAuthorityFixture;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\ManagedTransitionAuthorityFixture;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Factory;
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
        $requests = [];
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
        Http::fake(static function (Request $request) use ($fixture, &$requests): mixed {
            $requests[] = $request;

            return $fixture->respond($request);
        });

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
            ['handoff', 'managed-auth-v1', 'POST /managed-auth/v1/handoffs', $fixture->calls[0], $requests[0]],
            ['exchange', 'managed-auth-v1', 'POST /managed-auth/v1/handoffs/{request_id}/exchange', $fixture->calls[1], $requests[1]],
            ['confirm', 'managed-auth-v1', 'POST /managed-auth/v1/memberships/confirm', $fixture->calls[2], $requests[2]],
            ['ownership', 'managed-transition-v1', 'POST /managed-transition/v1/ownership', $fixture->calls[3], $requests[3]],
        ];

        foreach ($contracts as [$leg, $protocol, $endpoint, $call, $request]) {
            $this->assertDocumentedTransport($protocol, $endpoint, $request, $secret);
            $this->assertDocumentedPayload($protocol, $endpoint, 'Request fields', $call['body']);
            $this->assertDocumentedPayload($protocol, $endpoint, 'Response fields', $responses[$leg]);
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
        $this->assertDocumentedNestedPayload('Owner subject fields', $responses['ownership']['owner'], 'owner subject');
        $this->assertDocumentedNestedPayload(
            'Owner subject fields',
            $responses['ownership']['seated_owner'],
            'owner subject',
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
        $requests = [];
        $fixture->transform = static function (string $leg, array $payload) use (&$responses): array {
            $responses[$leg] = $payload;

            return $payload;
        };
        Http::fake(static function (Request $request) use ($fixture, &$requests): mixed {
            $requests[] = $request;

            return $fixture->respond($request);
        });
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

        foreach ($fixture->calls as $index => $call) {
            $body = json_decode($call['body'], true, flags: JSON_THROW_ON_ERROR);
            $endpoint = $endpoints[$call['leg']];
            $this->assertDocumentedTransport('managed-transition-v1', $endpoint, $requests[$index], $secret);
            $this->assertDocumentedPayload('managed-transition-v1', $endpoint, 'Request fields', $body);
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
            $this->assertDocumentedPayload('managed-transition-v1', $endpoint, 'Response fields', $responses[$leg]);
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
        foreach ($responses['T2']['members'] as $member) {
            $this->assertDocumentedNestedPayload('Roster member fields', $member, 'roster member');
        }
        $this->assertSame(
            $this->documentedFields(
                'POST /managed-transition/v1/transitions/{transition_id}/stage',
                'Mapping fields',
            ),
            array_keys($stageBody['mapping'][0]),
        );
        foreach ($stageBody['mapping'] as $element) {
            $this->assertDocumentedMappingElement($element);
        }
    }

    public function test_documented_refusals_match_real_clients_and_authority_fixtures(): void
    {
        $baseUrl = 'https://'.strtolower(Str::random(12)).'.example.test';
        $secret = bin2hex(random_bytes(32));
        $connection = new ManagedAuthConnection(
            'https://issuer-'.strtolower(Str::random(12)).'.example.test',
            (string) Str::uuid(),
            (string) Str::uuid(),
            (string) Str::uuid(),
            random_int(10, 100),
            $baseUrl,
            'wrong-'.$secret,
            null,
        );
        $authFixture = new ManagedAuthorityFixture(
            $baseUrl,
            $secret,
            $connection->issuer,
            $connection->connectionId,
            $connection->organizationId,
            $connection->installationId,
            $connection->authorityGeneration,
        );
        $authHttp = new Factory;
        $authFixtureResponse = null;
        $authHttp->fake(static function (Request $request) use ($authFixture, &$authFixtureResponse): mixed {
            return $authFixtureResponse = $authFixture->respond($request);
        });

        $authRefusal = $this->captureRefusal(
            fn () => (new ManagedAuthClient($authHttp))->createHandoff($connection, $this->opaqueKey()),
        );
        $authFixtureResponse = $authFixtureResponse?->wait();
        $authPayload = json_decode((string) $authFixtureResponse?->getBody(), true, flags: JSON_THROW_ON_ERROR);
        $this->assertSame(401, $authFixtureResponse?->getStatusCode());
        $this->assertSame('invalid_client', $authPayload['error']);
        $this->assertTrue($authRefusal->recordsFailedAttempt);
        $this->assertDocumentedRefusalResponse('managed-auth-v1', $authPayload);
        $this->assertDocumentedRefusal('managed-auth-v1 refusals', 401, 'invalid_client', 'refusal');

        $transitionFixtureResponse = null;
        [$owner, $transitionFixture, $transitions] = $this->configureTransition(
            ManagedTransitionDirection::Adopt,
            clientSecret: 'wrong-'.$secret,
            fixtureSecret: $secret,
            response: $transitionFixtureResponse,
        );
        $transitionRefusal = $this->captureRefusal(
            fn () => $transitions->prepare($owner, ManagedTransitionDirection::Adopt),
        );
        $transitionFixtureResponse = $transitionFixtureResponse?->wait();
        $transitionPayload = json_decode((string) $transitionFixtureResponse?->getBody(), true, flags: JSON_THROW_ON_ERROR);
        $this->assertSame(401, $transitionFixtureResponse?->getStatusCode());
        $this->assertSame('invalid_client', $transitionPayload['error']);
        $this->assertSame('invalid_client', $transitionRefusal->getMessage());
        $this->assertDocumentedRefusalResponse('managed-transition-v1', $transitionPayload);
        $this->assertDocumentedRefusal('managed-transition-v1 refusals', 401, 'invalid_client', 'refusal');

        $attempt = ManagedTransition::query()->sole();
        foreach ($this->documentedTable('managed-auth-v1 refusals') as $row) {
            $http = new Factory;
            $http->fake(['*' => $http->response([
                'contract_version' => 'managed-auth-v1',
                'error' => $row['error'],
            ], (int) $row['Status'], ['Retry-After' => '999'])]);
            $refusal = $this->captureRefusal(
                fn () => (new ManagedAuthClient($http))->createHandoff($connection, $this->opaqueKey()),
            );
            $this->assertSame(300, $refusal->retryAfterSeconds);
            $this->assertTrue($refusal->recordsFailedAttempt);
        }

        foreach ($this->documentedTable('managed-transition-v1 refusals') as $row) {
            $http = new Factory;
            $http->fake(['*' => $http->response([
                'contract_version' => 'managed-transition-v1',
                'error' => $row['error'],
            ], (int) $row['Status'], ['Retry-After' => '999'])]);
            $refusal = $this->captureRefusal(
                fn () => (new ManagedTransitionClient($http, $attempt))->prepare(),
            );
            $this->assertSame($row['error'], $refusal->getMessage());
            $this->assertSame(300, $refusal->retryAfterSeconds);
            $this->assertTrue($refusal->recordsFailedAttempt);
        }
    }

    public function test_documented_transition_conflict_is_emitted_by_the_real_fixture(): void
    {
        [$owner, $fixture, $transitions] = $this->configureTransition(ManagedTransitionDirection::Adopt);
        $transition = $transitions->prepare($owner, ManagedTransitionDirection::Adopt);
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
        $fixture->stageRosterChanged = true;

        $refusal = $this->captureRefusal(fn () => $transitions->stage($transition));

        $this->assertSame('roster_changed', $refusal->getMessage());
        $this->assertDocumentedRefusal('managed-transition-v1 refusals', 409, 'roster_changed', 'conflict-refusal');
    }

    public function test_documented_adopt_mapping_matrix_is_enforced_by_the_production_flow(): void
    {
        $this->assertDocumentedMappingMatrix(ManagedTransitionDirection::Adopt);
    }

    public function test_documented_exit_mapping_matrix_is_enforced_by_the_production_flow(): void
    {
        $this->assertDocumentedMappingMatrix(ManagedTransitionDirection::Exit);
    }

    public function test_documented_managed_user_binding_compatibility_is_enforced_by_the_production_flow(): void
    {
        $this->assertContains(
            'managed-user-binding',
            array_column($this->documentedTable('Complete-list constraints'), 'Constraint'),
        );
        [$owner, , $transitions] = $this->configureTransition(ManagedTransitionDirection::Exit);
        $owner->forceFill([
            'scalpels_issuer' => 'https://foreign-issuer-'.strtolower(Str::random(12)).'.example.test',
            'scalpels_connection_id' => (string) Str::uuid(),
            'scalpels_id' => 'direct-member',
        ])->save();
        $transition = $transitions->prepare($owner->refresh(), ManagedTransitionDirection::Exit);
        $transition = $transitions->fetchRoster($transition);

        $this->captureRefusal(fn () => $transitions->propose($transition, [[
            'scalpels_id' => 'direct-member',
            'local_kind' => 'user',
            'local_id' => (string) $owner->getKey(),
            'role' => 'member',
            'disposition' => 'link',
            'final_email' => strtolower(Str::random(12)).'@example.test',
        ]]));
        $this->assertSame(0, DB::table('bfc_managed_transition_mappings')->count());
    }

    public function test_documented_excluded_user_email_collision_is_enforced_by_the_production_flow(): void
    {
        $constraint = array_values(array_filter(
            $this->documentedTable('Complete-list constraints'),
            static fn (array $row): bool => $row['Constraint'] === 'unique-projected-email',
        ));
        $this->assertCount(1, $constraint);
        $this->assertStringContainsString('excluded users', $constraint[0]['Rule']);
        $this->assertStringContainsString('retained invitations', $constraint[0]['Rule']);
        [$owner, , $transitions] = $this->configureTransition(ManagedTransitionDirection::Adopt);
        $transition = $transitions->prepare($owner, ManagedTransitionDirection::Adopt);
        $transition = $transitions->fetchRoster($transition);

        $this->captureRefusal(fn () => $transitions->propose($transition, [
            [
                'scalpels_id' => 'direct-member',
                'local_kind' => null,
                'local_id' => null,
                'role' => 'member',
                'disposition' => 'create',
                'final_email' => strtoupper($owner->email),
            ],
            [
                'scalpels_id' => null,
                'local_kind' => 'user',
                'local_id' => (string) $owner->getKey(),
                'role' => null,
                'disposition' => 'exclude',
                'final_email' => null,
            ],
        ]));
        $this->assertSame(0, DB::table('bfc_managed_transition_mappings')->count());
    }

    private function assertDocumentedMappingMatrix(ManagedTransitionDirection $direction): void
    {
        $matrix = $this->documentedTable('Shape matrix');
        $directionColumn = $direction === ManagedTransitionDirection::Adopt ? 'Adopt' : 'Exit';
        $roster = [];
        foreach ($matrix as $row) {
            if ($row['scalpels_id'] !== 'required') {
                continue;
            }

            $roster[] = [
                'scalpels_id' => 'subject-'.$row['Shape'],
                'membership_status' => 'active',
                'role' => 'member',
                'display_name' => 'Member '.$row['Shape'],
                'contact_email' => $row['Shape'].'@example.test',
                'contact_email_verified' => true,
            ];
        }

        [$owner, , $transitions] = $this->configureTransition($direction, $roster);
        $allowed = array_values(array_filter(
            $matrix,
            static fn (array $row): bool => $row[$directionColumn] === 'allowed',
        ));
        $users = [$owner];
        $requiredUsers = count(array_filter(
            $allowed,
            static fn (array $row): bool => $row['local_kind'] === 'user',
        ));
        while (count($users) < $requiredUsers) {
            $users[] = User::query()->create([
                'name' => 'Mapping User '.Str::random(8),
                'email' => strtolower(Str::random(12)).'@example.test',
            ]);
        }
        $invitations = [];
        $requiredInvitations = count(array_filter(
            $allowed,
            static fn (array $row): bool => $row['local_kind'] === 'invitation',
        ));
        while (count($invitations) < $requiredInvitations) {
            $invitations[] = Invitation::query()->create([
                'id' => (string) Str::uuid(),
                'email' => strtolower(Str::random(12)).'@example.test',
                'token' => hash('sha256', Str::random(40)),
                'expires_at' => now()->addHour(),
            ]);
        }

        $userIndex = 0;
        $invitationIndex = 0;
        $mapping = [];
        foreach ($allowed as $row) {
            $localId = null;
            if ($row['local_kind'] === 'user') {
                $user = $users[$userIndex++];
                if ($row['Disposition'] === 'retain_deactivated') {
                    $this->makeAuthorityRemoved($user);
                }
                $localId = (string) $user->getKey();
            } elseif ($row['local_kind'] === 'invitation') {
                $localId = (string) $invitations[$invitationIndex++]->getKey();
            }
            $mapping[] = $this->mappingElementFromDocument($row, $localId);
        }

        foreach ($mapping as $element) {
            $this->assertDocumentedMappingElement($element);
        }
        $transition = $transitions->prepare($owner, $direction);
        $transition = $transitions->fetchRoster($transition);
        $proposed = $transitions->propose($transition, $mapping);
        $this->assertSame(count($mapping), DB::table('bfc_managed_transition_mappings')->count());

        foreach ($matrix as $row) {
            if ($row[$directionColumn] !== 'forbidden') {
                continue;
            }

            $candidate = $mapping;
            $localId = null;
            if ($row['local_kind'] !== 'null') {
                $replace = $this->mappingIndex(
                    $candidate,
                    static fn (array $element): bool => $element['local_kind'] === $row['local_kind']
                        && $element['disposition'] === 'exclude',
                );
                $localId = $candidate[$replace]['local_id'];
                $candidate[$replace] = $this->mappingElementFromDocument($row, $localId);
            } else {
                $candidate[] = $this->mappingElementFromDocument($row, null);
            }

            if ($row['Disposition'] === 'retain_deactivated') {
                $user = User::query()->findOrFail($localId);
                $this->makeAuthorityRemoved($user);
                $this->captureRefusal(fn () => $transitions->propose($proposed, $candidate));
                $user->forceFill([
                    'status' => 'active',
                    'password' => null,
                    'deactivated_at' => null,
                    'managed_membership_status' => null,
                ])->save();
            } else {
                $this->captureRefusal(fn () => $transitions->propose($proposed, $candidate));
            }
        }

        $this->assertInvalidDocumentedShapes($transitions, $proposed, $mapping, $direction);
        $this->assertDocumentedMappingBounds($transitions, $proposed, $mapping);
        $this->assertDocumentedCompletenessRules($transitions, $proposed, $mapping, $direction);
    }

    /** @param list<array<string, mixed>> $mapping */
    private function assertInvalidDocumentedShapes(
        ManagedTransitions $transitions,
        ManagedTransition $transition,
        array $mapping,
        ManagedTransitionDirection $direction,
    ): void {
        $mutations = [
            'link' => static function (array $element): array {
                $element['final_email'] = null;

                return $element;
            },
            'create' => static function (array $element) use ($mapping): array {
                $element['local_kind'] = 'user';
                $element['local_id'] = $mapping[array_key_first($mapping)]['local_id'] ?? '1';

                return $element;
            },
            'retain_local' => static function (array $element): array {
                $element['role'] = null;

                return $element;
            },
            'retain_deactivated' => static function (array $element): array {
                $element['role'] = 'member';

                return $element;
            },
            'exclude' => static function (array $element): array {
                $element['role'] = 'member';

                return $element;
            },
            'defer_to_managed_jit' => static function (array $element): array {
                $element['role'] = 'member';

                return $element;
            },
        ];

        foreach ($mutations as $disposition => $mutate) {
            $matches = array_keys(array_filter(
                $mapping,
                static fn (array $element): bool => $element['disposition'] === $disposition
                    && ($disposition !== 'retain_local' || $element['local_kind'] === 'user'),
            ));
            if ($matches === []) {
                continue;
            }

            $candidate = $mapping;
            $index = $matches[0];
            $candidate[$index] = $mutate($candidate[$index]);
            $this->captureRefusal(fn () => $transitions->propose($transition, $candidate));
        }

        $documentedDispositions = array_values(array_unique(array_column(
            $this->documentedTable('Shape matrix'),
            'Disposition',
        )));
        $this->assertSame(
            ['link', 'create', 'retain_local', 'retain_deactivated', 'exclude', 'defer_to_managed_jit'],
            $documentedDispositions,
        );
        $this->assertContains(
            $direction->value,
            ['adopt', 'exit'],
        );
    }

    /** @param list<array<string, mixed>> $mapping */
    private function assertDocumentedMappingBounds(
        ManagedTransitions $transitions,
        ManagedTransition $transition,
        array $mapping,
    ): void {
        $rules = [];
        foreach ($this->documentedTable('Mapping fields') as $row) {
            $rules[$row['Field']] = $row['Rules'];
        }

        foreach (['scalpels_id', 'local_id', 'final_email'] as $field) {
            preg_match('/(?:^|;)max-bytes=(\d+)(?:;|$)/', $rules[$field], $match);
            $this->assertNotEmpty($match, "The mapping {$field} rule has no byte bound.");
            $candidate = $mapping;
            $index = $this->mappingIndex(
                $candidate,
                static fn (array $element): bool => $element[$field] !== null,
            );
            $candidate[$index][$field] = str_repeat('x', ((int) $match[1]) + 1);
            $this->captureRefusal(fn () => $transitions->propose($transition, $candidate));
        }

        $candidate = $mapping;
        $index = $this->mappingIndex(
            $candidate,
            static fn (array $element): bool => $element['final_email'] !== null,
        );
        $candidate[$index]['final_email'] = 'not-an-email';
        $this->captureRefusal(fn () => $transitions->propose($transition, $candidate));
    }

    /** @param list<array<string, mixed>> $mapping */
    private function assertDocumentedCompletenessRules(
        ManagedTransitions $transitions,
        ManagedTransition $transition,
        array $mapping,
        ManagedTransitionDirection $direction,
    ): void {
        foreach ($this->documentedTable('Complete-list constraints') as $row) {
            $candidate = $mapping;
            switch ($row['Constraint']) {
                case 'known-subject':
                    $index = $this->mappingIndex($candidate, static fn (array $element): bool => $element['scalpels_id'] !== null);
                    $candidate[$index]['scalpels_id'] = 'unknown-subject';
                    break;
                case 'unique-subject':
                    $indexes = array_keys(array_filter($candidate, static fn (array $element): bool => $element['scalpels_id'] !== null));
                    $candidate[$indexes[1]]['scalpels_id'] = $candidate[$indexes[0]]['scalpels_id'];
                    break;
                case 'known-local':
                    $index = $this->mappingIndex($candidate, static fn (array $element): bool => $element['local_id'] !== null);
                    $candidate[$index]['local_id'] = 'unknown-local';
                    break;
                case 'managed-user-binding':
                    continue 2;
                case 'retain-deactivated-eligibility':
                    if ($direction !== ManagedTransitionDirection::Exit) {
                        continue 2;
                    }
                    $this->assertRetainDeactivatedEligibility($transitions, $transition, $mapping);

                    continue 2;
                case 'unique-local':
                    $indexes = array_keys(array_filter($candidate, static fn (array $element): bool => $element['local_id'] !== null));
                    $candidate[$indexes[1]]['local_kind'] = $candidate[$indexes[0]]['local_kind'];
                    $candidate[$indexes[1]]['local_id'] = $candidate[$indexes[0]]['local_id'];
                    break;
                case 'all-locals':
                    $index = $this->mappingIndex($candidate, static fn (array $element): bool => $element['disposition'] === 'exclude');
                    array_splice($candidate, $index, 1);
                    break;
                case 'all-adopt-subjects':
                    if ($direction !== ManagedTransitionDirection::Adopt) {
                        continue 2;
                    }
                    $index = $this->mappingIndex($candidate, static fn (array $element): bool => $element['disposition'] === 'defer_to_managed_jit');
                    array_splice($candidate, $index, 1);
                    break;
                case 'adopt-role-match':
                    if ($direction !== ManagedTransitionDirection::Adopt) {
                        continue 2;
                    }
                    $index = $this->mappingIndex($candidate, static fn (array $element): bool => in_array($element['disposition'], ['link', 'create'], true));
                    $candidate[$index]['role'] = 'admin';
                    break;
                case 'unique-projected-email':
                    $indexes = array_keys(array_filter($candidate, static fn (array $element): bool => $element['final_email'] !== null));
                    $candidate[$indexes[1]]['final_email'] = strtoupper((string) $candidate[$indexes[0]]['final_email']);
                    break;
                default:
                    $this->fail('No production-flow probe exists for documented mapping constraint '.$row['Constraint'].'.');
            }

            $this->captureRefusal(fn () => $transitions->propose($transition, $candidate));
        }
    }

    /** @param list<array<string, mixed>> $mapping */
    private function assertRetainDeactivatedEligibility(
        ManagedTransitions $transitions,
        ManagedTransition $transition,
        array $mapping,
    ): void {
        $index = $this->mappingIndex(
            $mapping,
            static fn (array $element): bool => $element['disposition'] === 'retain_deactivated',
        );
        $user = User::query()->findOrFail($mapping[$index]['local_id']);
        $invalidStates = [
            ['managed_membership_status' => 'active'],
            ['status' => 'active'],
            ['deactivated_at' => null],
            ['password' => 'not-null'],
        ];

        foreach ($invalidStates as $invalidState) {
            $this->makeAuthorityRemoved($user);
            $user->forceFill($invalidState)->save();
            $this->captureRefusal(fn () => $transitions->propose($transition, $mapping));
        }

        $this->makeAuthorityRemoved($user);
    }

    private function makeAuthorityRemoved(User $user): void
    {
        $user->forceFill([
            'status' => 'inactive',
            'password' => null,
            'deactivated_at' => now()->subMinute(),
            'managed_membership_status' => 'removed',
        ])->save();
    }

    /** @param array<string, string> $row @return array<string, ?string> */
    private function mappingElementFromDocument(array $row, ?string $localId): array
    {
        return [
            'scalpels_id' => $row['scalpels_id'] === 'required' ? 'subject-'.$row['Shape'] : null,
            'local_kind' => $row['local_kind'] === 'null' ? null : $row['local_kind'],
            'local_id' => $row['local_id'] === 'required' ? $localId : null,
            'role' => $row['role'] === 'required' ? 'member' : null,
            'disposition' => $row['Disposition'],
            'final_email' => $row['final_email'] === 'required' ? $row['Shape'].'-final@example.test' : null,
        ];
    }

    /**
     * @param  list<array<string, mixed>>  $mapping
     * @param  callable(array<string, mixed>): bool  $predicate
     */
    private function mappingIndex(array $mapping, callable $predicate): int
    {
        foreach ($mapping as $index => $element) {
            if ($predicate($element)) {
                return $index;
            }
        }

        $this->fail('The generated mapping has no element matching the requested probe.');
    }

    /**
     * @param  list<array<string, mixed>>|null  $roster
     * @return array{0: User, 1: ManagedTransitionAuthorityFixture, 2: ManagedTransitions}
     */
    private function configureTransition(
        ManagedTransitionDirection $direction,
        ?array $roster = null,
        ?string $clientSecret = null,
        ?string $fixtureSecret = null,
        mixed &$response = null,
    ): array {
        $clientSecret ??= bin2hex(random_bytes(32));
        $fixtureSecret ??= $clientSecret;
        $baseUrl = 'https://'.strtolower(Str::random(12)).'.example.test';
        $issuer = 'https://issuer-'.strtolower(Str::random(12)).'.example.test';
        $connectionId = (string) Str::uuid();
        $organizationId = (string) Str::uuid();
        $installationId = (string) Str::uuid();
        $generation = random_int(10, 100);
        DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
            'mode' => $direction->modeBefore()->value,
            'generation' => $generation,
            'issuer' => $issuer,
            'connection_id' => $connectionId,
            'organization_id' => $organizationId,
            'installation_id' => $installationId,
            'authority_base_url' => $baseUrl,
        ]);
        config([
            'built-for-cloud.managed.client_secret' => $clientSecret,
            'built-for-cloud.managed.ca_bundle' => null,
        ]);
        $owner = User::query()->create([
            'name' => 'Owner '.Str::random(12),
            'email' => strtolower(Str::random(12)).'@example.test',
        ]);
        $owner->forceFill(['role' => 'owner', 'status' => 'active'])->save();
        $fixture = new ManagedTransitionAuthorityFixture(
            baseUrl: $baseUrl,
            clientSecret: $fixtureSecret,
            issuer: $issuer,
            connectionId: $connectionId,
            organizationId: $organizationId,
            installationId: $installationId,
            generation: $generation,
        );
        if ($roster !== null) {
            $fixture->rosterPages = ['NULL' => $roster];
        }
        $http = new Factory;
        $http->fake(static function (Request $request) use ($fixture, &$response): mixed {
            return $response = $fixture->respond($request);
        });

        return [$owner->refresh(), $fixture, new ManagedTransitions($http)];
    }

    private function assertDocumentedTransport(
        string $protocol,
        string $endpoint,
        Request $request,
        string $secret,
    ): void {
        [, $path] = explode(' ', $endpoint, 2);
        $profiles = array_values(array_filter(
            $this->documentedTable('Executable transport profiles'),
            static fn (array $row): bool => $row['Protocol'] === $protocol && $row['Path'] === $path,
        ));
        $this->assertCount(1, $profiles, "The document needs exactly one transport profile for {$endpoint}.");
        $profile = $profiles[0];
        $pathPattern = preg_replace('/\\\\\{[^}]+\\\\\}/', '[^/]+', preg_quote($profile['Path'], '/'));
        $this->assertIsString($pathPattern);

        $this->assertSame($profile['Method'], $request->method());
        $this->assertMatchesRegularExpression('~^'.$pathPattern.'$~', (string) parse_url($request->url(), PHP_URL_PATH));
        $this->assertSame($profile['Accept'], $request->header('Accept')[0] ?? null);
        $this->assertStringStartsWith($profile['Content-Type'], $request->header('Content-Type')[0] ?? '');
        $this->assertSame(str_replace('enrolled-secret', $secret, $profile['Authorization']), $request->header('Authorization')[0] ?? null);
        [$header, $value] = explode(': ', $profile['Version header'], 2);
        $this->assertSame($value, $request->header($header)[0] ?? null);
        $this->assertSame('200', $profile['Success status']);
    }

    /** @param array<string, mixed> $payload */
    private function assertDocumentedPayload(
        string $protocol,
        string $endpoint,
        string $table,
        array $payload,
    ): void {
        $this->assertSame(
            $this->documentedFields($endpoint, $table),
            array_keys($payload),
            "{$endpoint} {$table} drifted from docs/managed-outbound-contract.md.",
        );
        $nullable = $this->documentedTable('Nullable locations');
        $common = [];
        foreach ($this->documentedTable('Common rules') as $row) {
            $common[$row['Field']] = $row;
        }

        foreach ($payload as $field => $value) {
            if ($value === null) {
                $matches = array_filter(
                    $nullable,
                    static fn (array $row): bool => $row['Method and path'] === $endpoint
                        && $row['Table'] === $table
                        && $row['Field'] === $field,
                );
                $this->assertCount(1, $matches, "{$endpoint} {$table}.{$field} is undocumented as nullable.");

                continue;
            }

            $this->assertArrayHasKey($field, $common, "{$field} has no executable common field rule.");
            $this->assertDocumentedValue($field, $value, $common[$field]['Type'], $common[$field]['Rules']);
            if ($protocol === 'managed-transition-v1'
                && $table === 'Response fields'
                && in_array($field, ['authority_generation', 'roster_version', 'response_sequence'], true)) {
                $this->assertContextualRules('managed-transition-v1 binding', $field, $value);
            }
            if ($endpoint === 'POST /managed-auth/v1/handoffs' && $table === 'Request fields' && $field === 'request_id') {
                $this->assertContextualRules('handoff request', $field, $value);
            }
            if ($endpoint === 'POST /managed-transition/v1/transitions' && $table === 'Request fields' && $field === 'transition_request_id') {
                $this->assertContextualRules('T1 request', $field, $value);
            }
            foreach ($this->documentedTable('Response enums') as $row) {
                if ($table === 'Response fields' && $row['Method and path'] === $endpoint && $row['Field'] === $field) {
                    $this->assertContains($value, explode(',', $row['Values']));
                }
            }
        }

        if (array_key_exists('contract_version', $payload)) {
            $this->assertSame($protocol, $payload['contract_version']);
        }
    }

    /** @param array<string, mixed> $payload */
    private function assertDocumentedNestedPayload(string $heading, array $payload, string $context): void
    {
        $rows = $this->documentedTable($heading);
        $this->assertSame(array_column($rows, 'Field'), array_keys($payload));
        $common = [];
        foreach ($this->documentedTable('Common rules') as $row) {
            $common[$row['Field']] = $row;
        }
        foreach ($payload as $field => $value) {
            $this->assertArrayHasKey($field, $common);
            $this->assertDocumentedValue($field, $value, $common[$field]['Type'], $common[$field]['Rules']);
            $this->assertContextualRules($context, $field, $value, required: false);
        }
    }

    /** @param array<string, mixed> $element */
    private function assertDocumentedMappingElement(array $element): void
    {
        $rules = $this->documentedTable('Mapping fields');
        $this->assertSame(array_column($rules, 'Field'), array_keys($element));
        foreach ($rules as $row) {
            $value = $element[$row['Field']];
            if ($value === null) {
                $this->assertSame('nullable', $row['Nullability']);

                continue;
            }
            $this->assertDocumentedValue($row['Field'], $value, $row['Type'], $row['Rules']);
        }
    }

    private function assertContextualRules(
        string $context,
        string $field,
        mixed $value,
        bool $required = true,
    ): void {
        $matches = array_values(array_filter(
            $this->documentedTable('Contextual rules'),
            static fn (array $row): bool => $row['Context'] === $context && $row['Field'] === $field,
        ));
        if (! $required && $matches === []) {
            return;
        }
        $this->assertCount(1, $matches, "The {$context}.{$field} contextual rule is missing or duplicated.");
        $this->assertDocumentedValue($field, $value, $this->phpTypeName($value), $matches[0]['Rules']);
    }

    private function assertDocumentedValue(string $field, mixed $value, string $type, string $rules): void
    {
        $this->assertSame($type, $this->phpTypeName($value), "{$field} has the wrong documented type.");
        foreach (explode(';', $rules) as $rule) {
            if ($rule === '' || in_array($rule, ['string', 'boolean', 'object', 'list'], true)) {
                continue;
            }
            if ($rule === 'non-empty') {
                $this->assertNotSame('', $value);
            } elseif ($rule === 'uint') {
                $this->assertGreaterThanOrEqual(0, $value);
            } elseif ($rule === 'rfc3339') {
                $this->assertMatchesRegularExpression(
                    '/\A\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])[Tt](?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d+)?(?:[Zz]|[+-](?:[01]\d|2[0-3]):[0-5]\d)\z/D',
                    $value,
                );
            } elseif ($rule === 'https-url') {
                $this->assertSame('https', parse_url($value, PHP_URL_SCHEME));
            } elseif ($rule === 'valid-email') {
                $this->assertNotFalse(filter_var($value, FILTER_VALIDATE_EMAIL));
            } elseif (str_starts_with($rule, 'enum=')) {
                $this->assertContains($value, explode(',', substr($rule, 5)));
            } elseif (str_starts_with($rule, 'max-bytes=')) {
                $this->assertLessThanOrEqual((int) substr($rule, 10), strlen($value));
            } elseif (str_starts_with($rule, 'bytes=')) {
                $this->assertSame((int) substr($rule, 6), strlen($value));
            } elseif (str_starts_with($rule, 'max-count=')) {
                $this->assertLessThanOrEqual((int) substr($rule, 10), count($value));
            } elseif (str_starts_with($rule, 'max=')) {
                $this->assertLessThanOrEqual((int) substr($rule, 4), $value);
            } else {
                $this->fail("No assertion implements documented rule {$field}:{$rule}.");
            }
        }
    }

    private function phpTypeName(mixed $value): string
    {
        return match (true) {
            is_string($value) => 'string',
            is_int($value) => 'integer',
            is_bool($value) => 'boolean',
            is_array($value) && array_is_list($value) => 'list',
            is_array($value) => 'object',
            default => get_debug_type($value),
        };
    }

    private function assertDocumentedRefusal(
        string $heading,
        int $status,
        string $error,
        string $classification,
    ): void {
        $matches = array_values(array_filter(
            $this->documentedTable($heading),
            static fn (array $row): bool => (int) $row['Status'] === $status && $row['error'] === $error,
        ));
        $this->assertCount(1, $matches, "{$status} {$error} is missing or duplicated in {$heading}.");
        $this->assertSame($classification, $matches[0]['Classification']);
        $this->assertSame('optional-decimal;cap=300', $matches[0]['Retry-After']);
    }

    private function assertDocumentedRefusalResponse(string $protocol, mixed $payload): void
    {
        $this->assertIsArray($payload);
        foreach ($this->documentedTable('Executable refusal response shape') as $row) {
            $this->assertSame('yes', $row['Required']);
            $this->assertArrayHasKey($row['Field'], $payload);
            $this->assertSame($row['Type'], $this->phpTypeName($payload[$row['Field']]));
        }
        $this->assertSame($protocol, $payload['contract_version']);
    }

    private function captureRefusal(callable $operation): ManagedAuthRefused
    {
        try {
            $operation();
        } catch (ManagedAuthRefused $exception) {
            return $exception;
        }

        $this->fail('The documented production refusal probe unexpectedly succeeded.');
    }

    /** @return list<string> */
    private function documentedFields(string $endpoint, string $table): array
    {
        $document = $this->document();
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

        return array_column($this->parseFirstTable($tableMatch[1]), 'Field');
    }

    /** @return list<array<string, string>> */
    private function documentedTable(string $heading): array
    {
        $matched = preg_match(
            '/^#{2,5} '.preg_quote($heading, '/').'\R(.*?)(?=^#{2,5} |\z)/ms',
            $this->document(),
            $section,
        );
        $this->assertSame(1, $matched, "The outbound contract has no {$heading} section.");

        return $this->parseFirstTable($section[1]);
    }

    /** @return list<array<string, string>> */
    private function parseFirstTable(string $section): array
    {
        $lines = preg_split('/\R/', $section);
        $this->assertIsArray($lines);
        foreach ($lines as $index => $line) {
            if (! str_starts_with($line, '|')
                || ! isset($lines[$index + 1])
                || preg_match('/^\|(?:\s*:?-+:?\s*\|)+$/', $lines[$index + 1]) !== 1) {
                continue;
            }

            $headers = $this->markdownCells($line);
            $rows = [];
            for ($rowIndex = $index + 2; isset($lines[$rowIndex]) && str_starts_with($lines[$rowIndex], '|'); $rowIndex++) {
                $cells = $this->markdownCells($lines[$rowIndex]);
                $this->assertCount(count($headers), $cells, 'A structured outbound-contract table row has the wrong column count.');
                $combined = array_combine($headers, $cells);
                $this->assertIsArray($combined);
                $rows[] = $combined;
            }
            $this->assertNotEmpty($rows, 'A structured outbound-contract table has no rows.');

            return $rows;
        }

        $this->fail('The documented section has no structured Markdown table.');
    }

    /** @return list<string> */
    private function markdownCells(string $line): array
    {
        $cells = array_slice(explode('|', $line), 1, -1);

        return array_map(
            static fn (string $cell): string => preg_replace('/^`(.*)`$/', '$1', trim($cell)) ?? '',
            $cells,
        );
    }

    private function document(): string
    {
        $document = file_get_contents(dirname(__DIR__).'/docs/managed-outbound-contract.md');
        $this->assertIsString($document);

        return $document;
    }

    private function opaqueKey(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }
}
