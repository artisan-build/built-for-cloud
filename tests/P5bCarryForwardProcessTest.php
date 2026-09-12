<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuditActorType;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureCredentialAdmin;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\SubjectType;
use Symfony\Component\Process\Process;

function p5bFreshDatabase(): string
{
    $database = tempnam(sys_get_temp_dir(), 'bfc-p5b-');

    if (! is_string($database)) {
        throw new RuntimeException('Could not create a P5b process-test database.');
    }

    return $database;
}

function p5bFreshSecret(string $prefix): string
{
    return $prefix.bin2hex(random_bytes(24));
}

function p5bFreshRun(string $scenario, string $phase, string $database, array $payload = []): array
{
    $process = new Process(
        [PHP_BINARY, __DIR__.'/Fixtures/p5b-carry-forward-worker.php', $scenario, $phase, $database],
        dirname(__DIR__),
    );
    $process->setInput(json_encode($payload, JSON_THROW_ON_ERROR));
    $process->setTimeout(60);
    $process->run();

    expect($process->isSuccessful())->toBeTrue($process->getErrorOutput());

    return json_decode($process->getOutput(), true, flags: JSON_THROW_ON_ERROR);
}

function p5bFreshAssertBoundary(array $results, array $phases): void
{
    expect(array_column($results, 'phase'))->toBe($phases)
        ->and(array_unique(array_column($results, 'pid')))->toHaveCount(count($results));
}

function p5bFreshById(array $rows, string $id): array
{
    foreach ($rows as $row) {
        if (($row['id'] ?? null) === $id) {
            return $row;
        }
    }

    throw new RuntimeException('Expected process-inspection row was absent: '.$id);
}

function p5bFreshCredential(string $id, string $hash, string $subjectType, string $subjectRef, array $abilities, array $extra = []): array
{
    return [
        'id' => $id,
        'secret_hash' => $hash,
        'subject_type' => $subjectType,
        'subject_ref' => $subjectRef,
        'abilities' => $abilities,
        ...$extra,
    ];
}

/**
 * Limit: committed SQLite persistence and a fresh application boot/request
 * only; not PostgreSQL FK behavior, real socket transport, or a live rung.
 */
it('persists an ownership claim as one linked unified owner credential in fresh processes', function (): void {
    $database = p5bFreshDatabase();
    $claimId = '11000000-0000-4000-8000-000000000001';
    $claimSecret = p5bFreshSecret('p5b-owner-claim-');

    try {
        $setup = p5bFreshRun('ownership-claim', 'setup', $database, [
            'claim_id' => $claimId,
            'claim_hash' => hash('sha256', $claimSecret),
        ]);
        $request = p5bFreshRun('ownership-claim', 'request', $database, ['claim_secret' => $claimSecret]);
        $inspect = p5bFreshRun('ownership-claim', 'inspect', $database, ['claim_id' => $claimId]);

        p5bFreshAssertBoundary([$setup, $request, $inspect], ['setup', 'request', 'inspect']);
        expect($request['status'])->toBe(201)
            ->and($request['response_keys'])->toBe(['owner_token', 'webhook_secret', 'product'])
            ->and($inspect['ownership_count'])->toBe(1)
            ->and($inspect['claim_id'])->toBe($claimId)
            ->and($inspect['claim_consumed'])->toBeTrue()
            ->and($inspect['owner_token_id'])->toBeNull()
            ->and($inspect['owner_credential_id'])->toBe($inspect['credential']['id'])
            ->and($inspect['credential_count'])->toBe(1)
            ->and($inspect['api_token_count'])->toBe(0)
            ->and($inspect['credential']['kind'])->toBe('bearer')
            ->and($inspect['credential']['subject_type'])->toBe(SubjectType::Operator->value)
            ->and($inspect['credential']['subject_ref'])->toBe('owner')
            ->and($inspect['credential']['name'])->toBe('owner')
            ->and($inspect['credential']['abilities'])->toBe([EnsureCredentialAdmin::ABILITY])
            ->and($inspect['credential']['status'])->toBe('active')
            ->and($inspect['credential']['secret_hash'])->toMatch('/^[0-9a-f]{64}$/');
    } finally {
        @unlink($database);
    }
});

/**
 * Limit: committed SQLite persistence and a fresh application boot/command
 * only; not PostgreSQL FK behavior, real socket transport, or a live rung.
 */
it('remints ownership into a new unified row and revokes every prior owner row in fresh processes', function (): void {
    $database = p5bFreshDatabase();
    $ownershipId = '12000000-0000-4000-8000-000000000001';
    $oldId = '12000000-0000-4000-8000-000000000002';
    $otherId = '12000000-0000-4000-8000-000000000003';
    $legacyId = '12000000-0000-4000-8000-000000000004';
    $newHash = bin2hex(random_bytes(32));
    $webhookSecret = hash('sha256', 'p5b-webhook-state');

    try {
        $setup = p5bFreshRun('ownership-remint', 'setup', $database, [
            'ownership_id' => $ownershipId,
            'webhook_secret' => $webhookSecret,
            'old_owner' => p5bFreshCredential($oldId, bin2hex(random_bytes(32)), SubjectType::Operator->value, 'owner', [EnsureCredentialAdmin::ABILITY]),
            'other_owner' => p5bFreshCredential($otherId, bin2hex(random_bytes(32)), SubjectType::Operator->value, 'owner', [EnsureCredentialAdmin::ABILITY]),
            'legacy_owner' => [
                'id' => $legacyId,
                'name' => 'owner',
                'token_hash' => bin2hex(random_bytes(32)),
                'abilities' => [Scope::Admin->value],
            ],
        ]);
        $command = p5bFreshRun('ownership-remint', 'command', $database, ['new_hash' => $newHash]);
        $inspect = p5bFreshRun('ownership-remint', 'inspect', $database, ['legacy_id' => $legacyId]);

        $old = p5bFreshById($inspect['credentials'], $oldId);
        $other = p5bFreshById($inspect['credentials'], $otherId);
        $new = p5bFreshById($inspect['credentials'], $inspect['owner_credential_id']);

        p5bFreshAssertBoundary([$setup, $command, $inspect], ['setup', 'command', 'inspect']);
        expect($command['exit'])->toBe(0)
            ->and($inspect['ownership_count'])->toBe(1)
            ->and($inspect['ownership_id'])->toBe($ownershipId)
            ->and($inspect['owner_token_id'])->toBeNull()
            ->and($inspect['owner_credential_id'])->not->toBeIn([$oldId, $otherId])
            ->and($inspect['webhook_secret'])->toBe($webhookSecret)
            ->and($inspect['credentials'])->toHaveCount(3)
            ->and($old['revoked'])->toBeTrue()
            ->and($other['revoked'])->toBeTrue()
            ->and($new['revoked'])->toBeFalse()
            ->and($new['subject_type'])->toBe(SubjectType::Operator->value)
            ->and($new['subject_ref'])->toBe('owner')
            ->and($new['abilities'])->toBe([EnsureCredentialAdmin::ABILITY])
            ->and($new['secret_hash'])->toBe($newHash)
            ->and($inspect['legacy']['id'])->toBe($legacyId)
            ->and($inspect['legacy']['revoked_at'])->not->toBeNull()
            ->and($inspect['legacy']['expires_at'])->not->toBeNull();
    } finally {
        @unlink($database);
    }
});

/**
 * Limit: committed SQLite persistence and a fresh application boot/request
 * only; not PostgreSQL FK behavior, real socket transport, or a live rung.
 */
it('admits only the exact dashboard metadata credential and persists its read audit in fresh processes', function (): void {
    $database = p5bFreshDatabase();
    $ids = [
        'exact' => '13000000-0000-4000-8000-000000000001',
        'non_operator' => '13000000-0000-4000-8000-000000000002',
        'superset' => '13000000-0000-4000-8000-000000000003',
        'legacy' => '13000000-0000-4000-8000-000000000004',
    ];
    $secrets = [
        'exact' => p5bFreshSecret('p5b-dashboard-exact-'),
        'non_operator' => p5bFreshSecret('p5b-dashboard-non-operator-'),
        'superset' => p5bFreshSecret('p5b-dashboard-superset-'),
        'legacy' => p5bFreshSecret('p5b-dashboard-legacy-'),
    ];

    try {
        $setup = p5bFreshRun('dashboard', 'setup', $database, [
            'credentials' => [
                p5bFreshCredential($ids['exact'], hash('sha256', $secrets['exact']), SubjectType::Operator->value, 'dashboard-exact', [OperatorAbility::MetadataRead->value]),
                p5bFreshCredential($ids['non_operator'], hash('sha256', $secrets['non_operator']), SubjectType::Application->value, 'dashboard-application', [OperatorAbility::MetadataRead->value]),
                p5bFreshCredential($ids['superset'], hash('sha256', $secrets['superset']), SubjectType::Operator->value, 'dashboard-superset', [OperatorAbility::MetadataRead->value, EnsureCredentialAdmin::ABILITY]),
            ],
            'legacy' => [
                'id' => $ids['legacy'],
                'name' => 'legacy-dashboard',
                'token_hash' => hash('sha256', $secrets['legacy']),
                'abilities' => [Scope::Admin->value],
            ],
        ]);
        $request = p5bFreshRun('dashboard', 'request', $database, ['bearers' => $secrets]);
        $inspect = p5bFreshRun('dashboard', 'inspect', $database, ['legacy_id' => $ids['legacy']]);

        $sensitive = array_values(array_filter($inspect['audit'], static fn (array $event): bool => $event['event'] === LifecycleEventType::SensitiveRead->value));
        $denied = array_values(array_filter($inspect['audit'], static fn (array $event): bool => $event['event'] === LifecycleEventType::DeniedAction->value));

        p5bFreshAssertBoundary([$setup, $request, $inspect], ['setup', 'request', 'inspect']);
        expect($request['statuses'])->toBe(['exact' => 200, 'non_operator' => 403, 'superset' => 403, 'legacy' => 401])
            ->and(p5bFreshById($inspect['credentials'], $ids['exact'])['last_used'])->toBeTrue()
            ->and($sensitive)->toHaveCount(1)
            ->and($sensitive[0]['credential_id'])->toBe($ids['exact'])
            ->and($sensitive[0]['actor_type'])->toBe(AuditActorType::OperatorIntegration->value)
            ->and($sensitive[0]['actor_ref'])->toBe($ids['exact'])
            ->and(array_column($denied, 'credential_id'))->toEqualCanonicalizing([$ids['non_operator'], $ids['superset']])
            ->and($inspect['legacy_request_count'])->toBe(0);
    } finally {
        @unlink($database);
    }
});

/**
 * Limit: committed SQLite persistence and a fresh application boot/request
 * only; not PostgreSQL FK behavior, real socket transport, or a live rung.
 */
it('offboards the subject and differently subjected same-user credentials while preserving an unrelated row in fresh processes', function (): void {
    $database = p5bFreshDatabase();
    $userId = '14000000-0000-4000-8000-000000000001';
    $ids = [
        'target' => '14000000-0000-4000-8000-000000000002',
        'bound' => '14000000-0000-4000-8000-000000000003',
        'already' => '14000000-0000-4000-8000-000000000004',
        'unrelated' => '14000000-0000-4000-8000-000000000005',
        'operator' => '14000000-0000-4000-8000-000000000006',
    ];
    $secrets = [
        'target' => p5bFreshSecret('p5b-offboard-target-'),
        'bound' => p5bFreshSecret('p5b-offboard-bound-'),
        'already' => p5bFreshSecret('p5b-offboard-already-'),
        'unrelated' => p5bFreshSecret('p5b-offboard-unrelated-'),
        'operator' => p5bFreshSecret('p5b-offboard-operator-'),
    ];
    $credentials = [
        p5bFreshCredential($ids['target'], hash('sha256', $secrets['target']), SubjectType::ExternalConsumer->value, 'p5b-target', [], ['user_id' => $userId]),
        p5bFreshCredential($ids['bound'], hash('sha256', $secrets['bound']), SubjectType::Application->value, 'p5b-other-subject', [], ['user_id' => $userId]),
        p5bFreshCredential($ids['already'], hash('sha256', $secrets['already']), SubjectType::Operator->value, 'p5b-already-revoked', [], ['user_id' => $userId, 'revoked_at' => '2026-01-01 00:00:00']),
        p5bFreshCredential($ids['unrelated'], hash('sha256', $secrets['unrelated']), SubjectType::Application->value, 'p5b-unrelated', []),
        p5bFreshCredential($ids['operator'], hash('sha256', $secrets['operator']), SubjectType::Operator->value, 'p5b-offboard-operator', [OperatorAbility::SubjectOffboard->value]),
    ];

    try {
        $setup = p5bFreshRun('offboard', 'setup', $database, [
            'user_id' => $userId,
            'email' => 'p5b-offboard-user@example.test',
            'credentials' => $credentials,
        ]);
        $request = p5bFreshRun('offboard', 'request', $database, [
            'target_subject' => 'p5b-target',
            'operator_secret' => $secrets['operator'],
        ]);
        $inspect = p5bFreshRun('offboard', 'inspect', $database);
        $verify = p5bFreshRun('offboard', 'verify', $database, ['bearers' => [
            'target' => $secrets['target'],
            'bound' => $secrets['bound'],
            'unrelated' => $secrets['unrelated'],
        ]]);
        $revoked = array_values(array_filter($inspect['audit'], static fn (array $event): bool => $event['event'] === LifecycleEventType::Revoked->value));

        p5bFreshAssertBoundary([$setup, $request, $inspect, $verify], ['setup', 'request', 'inspect', 'verify']);
        expect($request['status'])->toBe(200)
            ->and($request['body'])->toBe(['offboarded' => true, 'fully_contained' => false])
            ->and(p5bFreshById($inspect['credentials'], $ids['target'])['revoked'])->toBeTrue()
            ->and(p5bFreshById($inspect['credentials'], $ids['bound'])['revoked'])->toBeTrue()
            ->and(p5bFreshById($inspect['credentials'], $ids['already'])['revoked'])->toBeTrue()
            ->and(p5bFreshById($inspect['credentials'], $ids['unrelated'])['revoked'])->toBeFalse()
            ->and(array_column($revoked, 'credential_id'))->toEqualCanonicalizing([$ids['target'], $ids['bound']])
            ->and($verify['statuses'])->toBe(['target' => 401, 'bound' => 401, 'unrelated' => 200]);
    } finally {
        @unlink($database);
    }
});

/**
 * Limit: committed SQLite persistence and a fresh application boot/command
 * only; not PostgreSQL FK behavior, real socket transport, array-mail
 * delivery, or a live rung.
 */
it('warns for the selected unified expiry while ignoring an eligible legacy row in fresh processes', function (): void {
    $database = p5bFreshDatabase();
    $credentialId = '15000000-0000-4000-8000-000000000001';
    $legacyId = '15000000-0000-4000-8000-000000000002';
    $expiresAt = gmdate('Y-m-d H:i:s', time() + 86400);

    try {
        $setup = p5bFreshRun('expiry', 'setup', $database, [
            'credential' => p5bFreshCredential($credentialId, bin2hex(random_bytes(32)), SubjectType::Application->value, 'p5b-expiring', [], ['expires_at' => $expiresAt]),
            'legacy' => [
                'id' => $legacyId,
                'name' => 'p5b-expiring-legacy',
                'token_hash' => bin2hex(random_bytes(32)),
                'abilities' => [Scope::Consume->value],
                'expires_at' => $expiresAt,
            ],
        ]);
        $command = p5bFreshRun('expiry', 'command', $database);
        $inspect = p5bFreshRun('expiry', 'inspect', $database, [
            'credential_id' => $credentialId,
            'legacy_id' => $legacyId,
        ]);
        $expiring = array_values(array_filter($inspect['audit'], static fn (array $event): bool => $event['event'] === LifecycleEventType::Expiring->value));

        p5bFreshAssertBoundary([$setup, $command, $inspect], ['setup', 'command', 'inspect']);
        expect($command['exit'])->toBe(0)
            ->and($inspect['credential_id'])->toBe($credentialId)
            ->and($inspect['expires_at'])->toBe($expiresAt)
            ->and($expiring)->toHaveCount(1)
            ->and($expiring[0]['credential_id'])->toBe($credentialId)
            ->and($expiring[0]['credential_expires_at'])->toBe($expiresAt)
            ->and($inspect['legacy_expiring_events'])->toBe(0);
    } finally {
        @unlink($database);
    }
});

/**
 * Limit: committed SQLite persistence and a fresh application boot/request
 * only; not PostgreSQL FK behavior, real socket transport, or a live rung.
 */
it('persists all four K7 exact-ability transitions and refuses wrong abilities in fresh processes', function (): void {
    $database = p5bFreshDatabase();
    $ownershipId = '16000000-0000-4000-8000-000000000001';
    $initialClaimId = '16000000-0000-4000-8000-000000000002';
    $ids = [
        'owner' => '16000000-0000-4000-8000-000000000003',
        'release_exact' => '16000000-0000-4000-8000-000000000004',
        'release_wrong' => '16000000-0000-4000-8000-000000000005',
        'issue_exact' => '16000000-0000-4000-8000-000000000006',
        'issue_wrong' => '16000000-0000-4000-8000-000000000007',
        'observations_exact' => '16000000-0000-4000-8000-000000000008',
        'observations_wrong' => '16000000-0000-4000-8000-000000000009',
    ];
    $secrets = array_combine(
        array_keys($ids),
        array_map(static fn (string $name): string => p5bFreshSecret('p5b-route-'.$name.'-'), array_keys($ids)),
    );
    $credentials = [
        p5bFreshCredential($ids['owner'], hash('sha256', $secrets['owner']), SubjectType::Operator->value, 'owner', [EnsureCredentialAdmin::ABILITY]),
        p5bFreshCredential($ids['release_exact'], hash('sha256', $secrets['release_exact']), SubjectType::Operator->value, 'release-exact', [OperatorAbility::OwnershipRelease->value]),
        p5bFreshCredential($ids['release_wrong'], hash('sha256', $secrets['release_wrong']), SubjectType::Operator->value, 'release-wrong', [OperatorAbility::CredentialRead->value]),
        p5bFreshCredential($ids['issue_exact'], hash('sha256', $secrets['issue_exact']), SubjectType::Operator->value, 'issue-exact', [OperatorAbility::CredentialMint->value]),
        p5bFreshCredential($ids['issue_wrong'], hash('sha256', $secrets['issue_wrong']), SubjectType::Operator->value, 'issue-wrong', [OperatorAbility::CredentialRead->value]),
        p5bFreshCredential($ids['observations_exact'], hash('sha256', $secrets['observations_exact']), SubjectType::Operator->value, 'observations-exact', [OperatorAbility::CredentialRead->value]),
        p5bFreshCredential($ids['observations_wrong'], hash('sha256', $secrets['observations_wrong']), SubjectType::Operator->value, 'observations-wrong', [OperatorAbility::CredentialMint->value]),
    ];
    $issueEmail = 'p5b-route-issue@example.test';

    try {
        $setup = p5bFreshRun('operator-routes', 'setup', $database, [
            'credentials' => $credentials,
            'ownership_id' => $ownershipId,
            'owner_credential_id' => $ids['owner'],
            'initial_claim_id' => $initialClaimId,
            'initial_claim_hash' => bin2hex(random_bytes(32)),
        ]);
        $request = p5bFreshRun('operator-routes', 'request', $database, [
            'cancel_wrong' => $secrets['release_wrong'],
            'release_exact' => $secrets['release_exact'],
            'release_wrong' => $secrets['release_wrong'],
            'issue_exact' => $secrets['issue_exact'],
            'issue_wrong' => $secrets['issue_wrong'],
            'issue_email' => $issueEmail,
            'observations_exact' => $secrets['observations_exact'],
            'observations_wrong' => $secrets['observations_wrong'],
        ]);
        $inspect = p5bFreshRun('operator-routes', 'inspect', $database, [
            'ownership_id' => $ownershipId,
            'initial_claim_id' => $initialClaimId,
        ]);
        $deniedRefs = array_column(array_values(array_filter(
            $inspect['audit'],
            static fn (array $event): bool => $event['event'] === LifecycleEventType::DeniedAction->value,
        )), 'actor_ref');

        p5bFreshAssertBoundary([$setup, $request, $inspect], ['setup', 'request', 'inspect']);
        expect($request['statuses'])->toBe([
            'cancel_wrong' => 403,
            'cancel_exact' => 200,
            'release_wrong' => 403,
            'release_exact' => 201,
            'issue_wrong' => 403,
            'issue_exact' => 201,
            'observations_wrong' => 403,
            'observations_exact' => 200,
        ])->and($inspect['initial_claim_consumed'])->toBeTrue()
            ->and($inspect['pending_claim_is_new'])->toBeTrue()
            ->and($inspect['pending_claim_consumed'])->toBeFalse()
            ->and($inspect['claim_count'])->toBe(2)
            ->and($inspect['onboarding_count'])->toBe(1)
            ->and($inspect['onboarding'])->toBe(['email' => $issueEmail, 'scope' => Scope::Consume->value, 'consumed' => false])
            ->and($deniedRefs)->toEqualCanonicalizing([
                $ids['release_wrong'],
                $ids['release_wrong'],
                $ids['issue_wrong'],
                $ids['observations_wrong'],
            ])
            ->and(p5bFreshById($inspect['credentials'], $ids['release_exact'])['last_used'])->toBeTrue()
            ->and(p5bFreshById($inspect['credentials'], $ids['release_wrong'])['last_used'])->toBeTrue()
            ->and(p5bFreshById($inspect['credentials'], $ids['issue_exact'])['last_used'])->toBeTrue()
            ->and(p5bFreshById($inspect['credentials'], $ids['issue_wrong'])['last_used'])->toBeTrue()
            ->and(p5bFreshById($inspect['credentials'], $ids['observations_exact'])['last_used'])->toBeTrue()
            ->and(p5bFreshById($inspect['credentials'], $ids['observations_wrong'])['last_used'])->toBeTrue();
    } finally {
        @unlink($database);
    }
});

/**
 * Limit: committed SQLite persistence and a fresh application boot/request
 * only; not PostgreSQL FK behavior, real socket transport, or a live rung.
 */
it('persists exact authenticated client identity separately from unauthenticated observation and reads it in fresh processes', function (): void {
    $database = p5bFreshDatabase();
    $credentialId = '17000000-0000-4000-8000-000000000001';
    $secret = p5bFreshSecret('p5b-client-identity-reader-');
    $authenticatedIdentity = 'P5b Client/Case Sensitive';
    $unauthenticatedIdentity = 'P5b Advisory Observer';

    try {
        $setup = p5bFreshRun('client-identity', 'setup', $database, [
            'credential' => p5bFreshCredential(
                $credentialId,
                hash('sha256', $secret),
                SubjectType::Operator->value,
                'p5b-client-reader',
                [OperatorAbility::CredentialRead->value],
            ),
        ]);
        $request = p5bFreshRun('client-identity', 'request', $database, [
            'secret' => $secret,
            'authenticated_identity' => $authenticatedIdentity,
            'unauthenticated_identity' => $unauthenticatedIdentity,
        ]);
        $inspect = p5bFreshRun('client-identity', 'inspect', $database, ['credential_id' => $credentialId]);

        p5bFreshAssertBoundary([$setup, $request, $inspect], ['setup', 'request', 'inspect']);
        expect($request['statuses'])->toBe(['authenticated' => 200, 'unauthenticated' => 401, 'read' => 200])
            ->and($request['read_enabled'])->toBeTrue()
            ->and($request['read_observations'])->toBe([$unauthenticatedIdentity])
            ->and($inspect['credential']['id'])->toBe($credentialId)
            ->and($inspect['credential']['client_identity'])->toBe($authenticatedIdentity)
            ->and($inspect['credential']['client_identity_last_seen'])->toBeTrue()
            ->and($inspect['credential']['last_used'])->toBeTrue()
            ->and($inspect['observations'])->toBe([[
                'client_identity' => $unauthenticatedIdentity,
                'client_identity_hash' => hash('sha256', $unauthenticatedIdentity),
                'observation_count' => 1,
                'first_seen' => true,
                'last_seen' => true,
            ]]);
    } finally {
        @unlink($database);
    }
});

/**
 * Limit: committed SQLite persistence and a fresh application boot/request
 * through a Testbench probe route only; not PostgreSQL FK behavior, real MCP
 * socket transport, or a live rung.
 */
it('persists MCP bearer usage and exposes only operator admin attribution through a fresh-process probe route', function (): void {
    $database = p5bFreshDatabase();
    $ids = [
        'non_admin' => '18000000-0000-4000-8000-000000000001',
        'operator_admin' => '18000000-0000-4000-8000-000000000002',
        'application_admin' => '18000000-0000-4000-8000-000000000003',
    ];
    $secrets = [
        'non_admin' => p5bFreshSecret('p5b-mcp-non-admin-'),
        'operator_admin' => p5bFreshSecret('p5b-mcp-operator-admin-'),
        'application_admin' => p5bFreshSecret('p5b-mcp-application-admin-'),
    ];

    try {
        $setup = p5bFreshRun('mcp', 'setup', $database, ['credentials' => [
            p5bFreshCredential($ids['non_admin'], hash('sha256', $secrets['non_admin']), SubjectType::Operator->value, 'mcp-non-admin', ['apps:call']),
            p5bFreshCredential($ids['operator_admin'], hash('sha256', $secrets['operator_admin']), SubjectType::Operator->value, 'mcp-operator-admin', [EnsureCredentialAdmin::ABILITY]),
            p5bFreshCredential($ids['application_admin'], hash('sha256', $secrets['application_admin']), SubjectType::Application->value, 'mcp-application-admin', [EnsureCredentialAdmin::ABILITY]),
        ]]);
        $request = p5bFreshRun('mcp', 'request', $database, ['bearers' => $secrets]);
        $inspect = p5bFreshRun('mcp', 'inspect', $database);

        p5bFreshAssertBoundary([$setup, $request, $inspect], ['setup', 'request', 'inspect']);

        foreach ($ids as $name => $id) {
            expect($request['responses'][$name]['status'])->toBe(200)
                ->and($request['responses'][$name]['body']['principal_type'])->toBe(Credential::class)
                ->and($request['responses'][$name]['body']['principal_id'])->toBe($id)
                ->and($request['responses'][$name]['body']['actor_token_id'])->toBeNull()
                ->and($request['responses'][$name]['body']['authorization_scrubbed'])->toBeTrue()
                ->and(p5bFreshById($inspect['credentials'], $id)['last_used'])->toBeTrue()
                ->and(p5bFreshById($inspect['credentials'], $id)['client_identity'])->toBe('p5b-mcp-'.$name);
        }

        expect($request['responses']['non_admin']['body']['actor_credential_id'])->toBeNull()
            ->and($request['responses']['non_admin']['body']['audit_type'])->toBeNull()
            ->and($request['responses']['application_admin']['body']['actor_credential_id'])->toBeNull()
            ->and($request['responses']['application_admin']['body']['audit_type'])->toBeNull()
            ->and($request['responses']['operator_admin']['body']['actor_credential_id'])->toBe($ids['operator_admin'])
            ->and($request['responses']['operator_admin']['body']['audit_type'])->toBe(AuditActorType::OperatorIntegration->value)
            ->and($request['responses']['operator_admin']['body']['audit_ref'])->toBe($ids['operator_admin'])
            ->and($inspect['admin_token_audit_count'])->toBe(0);
    } finally {
        @unlink($database);
    }
});
