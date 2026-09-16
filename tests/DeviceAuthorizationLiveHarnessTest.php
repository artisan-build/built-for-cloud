<?php

declare(strict_types=1);

use Symfony\Component\Process\Process;

it('ships a syntax-valid disposable device authorization harness and private stamp schema', function (): void {
    $root = dirname(__DIR__);
    $harness = $root.'/tests/Live/run-device-authorization-harness.php';
    $state = $root.'/tests/Live/device-authorization-state.php';
    $server = $root.'/tests/Live/asymmetric-enrollment-server.php';
    $schemaPath = $root.'/tests/Live/device-authorization-stamp.schema.json';

    foreach ([$harness, $state, $server] as $phpFile) {
        $process = new Process([PHP_BINARY, '-l', $phpFile]);
        expect($process->run())->toBe(0, $process->getErrorOutput());
    }

    $schema = json_decode((string) file_get_contents($schemaPath), true, flags: JSON_THROW_ON_ERROR);
    $source = (string) file_get_contents($harness);
    $stateSource = (string) file_get_contents($state);

    expect($schema['properties']['schema']['const'] ?? null)->toBe('bfc.device-authorization.live.v1')
        ->and($schema['properties']['cases']['required'] ?? [])->toContain(
            'same_user_clean_context_refusal',
            'cross_user_refusal',
            'device_submission_nonce_refusals',
            'device_decision_replay_refusal',
            'device_terminal_binding_cleanup',
            'device_managed_authority_transition',
            'device_approve_exchange_and_bound_use',
            'device_single_token_exchange',
            'device_concurrent_token_exchange',
            'device_pending_slow_down_and_deny',
            'device_expiry',
            'transport_limiter_refusal_before_effect',
            'loopback_callback_pkce_and_bound_use',
            'loopback_cross_browser_refusal',
            'loopback_deny',
            'exact_bound_refusal_matrix',
            'app_purpose_mapping_drift',
            'final_state',
        )
        ->and($source)->toContain(
            'isolated_cookie_jars',
            'bounded_readiness',
            'bounded_teardown',
            'stamp_contains_secrets',
            'set-credential-dimension',
            'create-unbound-bearer',
            '/_bfc-harness/device/use-legacy',
            "'algorithm' => 'RS256',",
            "if (! \$follow) {\n        \$config[] = 'request = \"'.\$method.'\"';",
            "if (\$follow) {\n        \$config[] = 'location';",
            "\$config[] = 'data-binary = \"@'.deviceHarnessConfigValue(\$requestBody).'\"';",
            "'operation' => 'reset-effects'",
            "'operation' => 'device-exchange'",
            "'operation' => 'clear-decision-limiters'",
            "['operation' => 'managed-authority', 'state' => 'positive']",
            "['operation' => 'managed-authority', 'state' => 'inactive']",
            "['operation' => 'managed-authority', 'state' => 'local']",
            "\$secrets[] = \$managed['device_code'];\n    \$secrets[] = \$managed['user_code'];",
            "'operation' => 'device-decision'",
            "str_contains(\$managedDecision['body'], 'device-authorization-unavailable')",
            "'denial_reason' => 'authority_denied'",
            "'submission_nonce_consumed' => false",
            "'binding_removed' => true",
            "\$effectCanaries = ['authorize_calls', 'limiter_attempts', 'usage_calls', 'last_used_at', 'client_identity', 'domain_handler_calls'];",
            'The exact-bound positive control did not change',
            '$wrongPurposeAfter === $wrongPurposeBefore',
            '$mappingDriftAfter === $mappingDriftBefore',
            "'drift_status' => \$mappingDriftStatus",
            "'restored_status' => \$mappingRestoredStatus",
            'deviceHarnessConcurrentTokenExchange($runDirectory, $concurrentBaseUrl, $concurrentExchange[\'device_code\'], $inspectedArgv)',
            "\$refusals[0]['body'] === ['error' => 'invalid_grant']",
            "'barrier_arrivals' => 2",
            "'bearer_successes' => 1",
            "'invalid_grant_refusals' => 1",
            "'credential_rows' => 1",
            '$afterEffects === $beforeEffects',
            'deviceHarnessEffects($runDirectory, $baseUrl, $credentialId) === $legacyBefore',
            'deviceHarnessEffects($runDirectory, $baseUrl, $unboundId) === $unboundBefore',
            '$loopbackWrongPurposeAfter === $loopbackWrongPurposeBefore',
            'deviceHarnessContainsSecret($serverContents, $secrets)',
            'deviceHarnessContainsSecret($inspectedArgv, $secrets)',
            'deviceHarnessContainsSecret($stamp, $secrets)',
            'header = "X-BfC-Client-Id: ',
        )
        ->and($stateSource)->toContain(
            "if (\$input['operation'] === 'reset-effects')",
            "if (\$input['operation'] === 'managed-authority')",
            "->where('managed_connection_status', 'active')",
            "->update(['managed_connection_status' => 'inactive'])",
            "if (\$input['operation'] === 'device-decision')",
            "'submission_nonce_present' => DB::table('bfc_submission_nonces')",
            "Schema::create('bfc_device_harness_effects'",
            "'last_used_at' => '2000-01-01 00:00:00'",
            "RateLimiter::clear('bfc-device-harness-use|'.\$credentialId)",
            "if (\$input['operation'] === 'device-exchange')",
            "if (\$input['operation'] === 'clear-decision-limiters')",
            "RateLimiter::clear(md5('bfc-authorization-decision'.'bfc-authorization-decision|'",
            "'credential_rows' => is_string(\$authorization->issued_credential_id)",
        )
        ->and(substr_count($source, "\$config[] = 'request = \"'.\$method.'\"';"))->toBe(1)
        ->and($source)->not->toContain(
            'cloud command:',
            'cloud environment:',
            'Authorization: Bearer {$',
            "'algorithm' => 'rs256',",
            'post303',
            "['server_log_clean' => false, 'argv_clean' => false, 'stamp_contains_secrets' => false]",
        );
});

it('keeps every exact-bound effect canary durable and independently observable', function (): void {
    $provider = (string) file_get_contents(__DIR__.'/Support/StandaloneHarnessServiceProvider.php');
    $declaration = (string) file_get_contents(__DIR__.'/Fixtures/DeviceFlowDeclaration.php');

    expect($declaration)->toContain(
        "Schema::hasTable('bfc_device_harness_effects')",
        "->increment('authorize_calls')",
    )
        ->and($provider)->toContain(
            "database.connections.sqlite.transaction_mode', 'IMMEDIATE'",
            "database.connections.sqlite.busy_timeout', 10_000",
            'DB::listen(static function (QueryExecuted $query): void',
            "->increment('usage_calls')",
            "RateLimiter::hit('bfc-device-harness-use|'.\$credential->id, 60)",
            "->increment('domain_handler_calls')",
            "'authorize_calls' => (int) \$effects->authorize_calls",
            "'limiter_attempts' => RateLimiter::attempts('bfc-device-harness-use|'.\$credential)",
            "'usage_calls' => (int) \$effects->usage_calls",
            "'last_used_at' => \$row->last_used_at?->toAtomString()",
            "'client_identity' => \$row->client_identity",
            "'domain_handler_calls' => (int) \$effects->domain_handler_calls",
        )
        ->and($provider)->not->toContain("'authorize_calls' => DeviceFlowDeclaration::\$authorizeCalls");
});

it('keeps both disposable clients bounded and keeps secrets out of argv', function (): void {
    $root = dirname(__DIR__);
    $device = (string) file_get_contents($root.'/tests/Fixtures/Clients/device-client.sh');
    $loopback = (string) file_get_contents($root.'/tests/Fixtures/Clients/loopback-client.php');

    expect($device)->toContain(
        'IFS= read -r device_code',
        '[ "$attempt" -lt 180 ]',
        'chmod 600 "$bearer_file"',
        'curl --silent --show-error --dump-header "$headers" --output "$body" --config -',
        'connect-timeout = 5',
        'max-time = 15',
    )->not->toContain('device-client.sh <base-url> <device-code>')
        ->and($loopback)->toContain(
            "stream_socket_server('tcp://127.0.0.1:0'",
            'stream_select($read, $write, $except, 180)',
            'hash_equals($state',
            'chmod($bearerFile, 0600)',
            'unset($accessToken, $body, $callback, $verifier, $state)',
        )->not->toContain('<code-verifier>', '<state>');
});

it('keeps installation live profiles and protected use free of unknown abilities', function (): void {
    $provider = (string) file_get_contents(__DIR__.'/Support/StandaloneHarnessServiceProvider.php');

    expect($provider)->toContain(
        "foreach (['live.device', 'live.loopback'] as \$purpose)",
        "CredentialAuthorizationOwnership::Installation,\n                    [],",
        'authenticate($request, $purpose);',
        "\$request->header('X-Bfc-Harness-App-Purpose-Mapping') === 'drift'",
        "'live.device' => CredentialPurpose::Mcp->value",
        "config()->set('built-for-cloud.credentials.app_purposes', \$mapping);",
    )->not->toContain('harness:use');
});

it('coordinates concurrent real HTTP token requests before the package route executes', function (): void {
    $server = (string) file_get_contents(__DIR__.'/Live/asymmetric-enrollment-server.php');
    $harness = (string) file_get_contents(__DIR__.'/Live/run-device-authorization-harness.php');

    expect($server)->toContain(
        "parse_url((string) (\$_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH) === '/bfc/device/token'",
        'touch("{$barrierDirectory}/{$barrier}-{$worker}.ready")',
        'is_file("{$barrierDirectory}/{$barrier}-1.ready")',
        'is_file("{$barrierDirectory}/{$barrier}-2.ready")',
        '$deadline = hrtime(true) + 10_000_000_000;',
        "require __DIR__.'/../../vendor/orchestra/testbench-core/laravel/public/index.php';",
    )->and($harness)->toContain(
        "'PHP_CLI_SERVER_WORKERS' => '4'",
        '$concurrentServer = new Process([',
        'deviceHarnessStopServer($concurrentServer);',
        "'concurrent_http_workers' => 4",
        "'concurrent_request_barrier' => true",
        "'header = \"X-Bfc-Harness-Concurrent-Exchange: '.\$barrier.'\"'",
        "'header = \"X-Bfc-Harness-Concurrent-Worker: '.\$worker.'\"'",
        "new Process(['curl', '--config', '-'], timeout: 20)",
    )->not->toContain('device_code = "');
});
