<?php

declare(strict_types=1);

use Symfony\Component\Process\Process;

it('ships a syntax-valid disposable device authorization harness and private stamp schema', function (): void {
    $root = dirname(__DIR__);
    $harness = $root.'/tests/Live/run-device-authorization-harness.php';
    $state = $root.'/tests/Live/device-authorization-state.php';
    $schemaPath = $root.'/tests/Live/device-authorization-stamp.schema.json';

    foreach ([$harness, $state] as $phpFile) {
        $process = new Process([PHP_BINARY, '-l', $phpFile]);
        expect($process->run())->toBe(0, $process->getErrorOutput());
    }

    $schema = json_decode((string) file_get_contents($schemaPath), true, flags: JSON_THROW_ON_ERROR);
    $source = (string) file_get_contents($harness);

    expect($schema['properties']['schema']['const'] ?? null)->toBe('bfc.device-authorization.live.v1')
        ->and($schema['properties']['cases']['required'] ?? [])->toContain(
            'same_user_clean_context_refusal',
            'cross_user_refusal',
            'device_submission_nonce_refusals',
            'device_decision_replay_refusal',
            'device_terminal_binding_cleanup',
            'device_approve_exchange_and_bound_use',
            'device_pending_slow_down_and_deny',
            'device_expiry',
            'transport_limiter_refusal_before_effect',
            'loopback_callback_pkce_and_bound_use',
            'loopback_cross_browser_refusal',
            'loopback_deny',
            'exact_bound_refusal_matrix',
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
        )
        ->and(substr_count($source, "\$config[] = 'request = \"'.\$method.'\"';"))->toBe(1)
        ->and($source)->not->toContain(
            'cloud command:',
            'cloud environment:',
            'Authorization: Bearer {$',
            "'algorithm' => 'rs256',",
            'post303',
        );
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
    )->not->toContain('harness:use');
});
