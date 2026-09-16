<?php

declare(strict_types=1);

use Illuminate\Foundation\Application;
use Symfony\Component\Process\Process;

require __DIR__.'/../../vendor/autoload.php';

/** @return never */
function failDeviceHarness(string $message): void
{
    throw new RuntimeException($message);
}

function deviceHarnessAssert(bool $condition, string $message): void
{
    if (! $condition) {
        failDeviceHarness($message);
    }
}

function deviceHarnessRun(Process $process, string $label, ?string $input = null, ?int $expectedExit = 0): string
{
    if ($input !== null) {
        $process->setInput($input);
    }

    $exit = $process->run();

    if ($expectedExit !== null && $exit !== $expectedExit) {
        failDeviceHarness("{$label} exited unexpectedly.");
    }

    return $process->getOutput();
}

function deviceHarnessPort(): int
{
    $socket = stream_socket_server('tcp://127.0.0.1:0', $errorNumber, $error);

    if (! is_resource($socket)) {
        failDeviceHarness('The OS could not allocate a loopback port.');
    }

    $address = stream_socket_get_name($socket, false);
    fclose($socket);
    $port = is_string($address) ? parse_url('tcp://'.$address, PHP_URL_PORT) : false;

    return is_int($port) ? $port : failDeviceHarness('The allocated loopback port was unreadable.');
}

function deviceHarnessConfigValue(string $value): string
{
    return str_replace(['\\', '"', "\r", "\n"], ['\\\\', '\\"', '', '\\n'], $value);
}

/** @param list<string> $secrets */
function deviceHarnessContainsSecret(mixed $value, array $secrets): bool
{
    $serialized = json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

    foreach ($secrets as $secret) {
        if ($secret !== '' && str_contains($serialized, $secret)) {
            return true;
        }
    }

    return false;
}

/** @param list<string> $secrets */
function deviceHarnessRedactSecrets(mixed $value, array $secrets): mixed
{
    if (is_array($value)) {
        foreach ($value as $key => $member) {
            $value[$key] = deviceHarnessRedactSecrets($member, $secrets);
        }

        return $value;
    }

    if (! is_string($value)) {
        return $value;
    }

    return str_replace($secrets, '[redacted]', $value);
}

/** @return array{status: int, body: string, headers: string} */
function deviceHarnessHttp(
    string $runDirectory,
    string $context,
    string $method,
    string $url,
    ?string $body = null,
    ?string $contentType = null,
    array $headers = [],
    bool $follow = false,
): array {
    static $request = 0;
    $request++;
    $responseBody = "{$runDirectory}/http-{$request}.body";
    $responseHeaders = "{$runDirectory}/http-{$request}.headers";
    $requestBody = "{$runDirectory}/http-{$request}.request";
    $cookieJar = "{$runDirectory}/browser-{$context}.cookies";
    $config = [
        'silent',
        'show-error',
        'url = "'.deviceHarnessConfigValue($url).'"',
        'output = "'.deviceHarnessConfigValue($responseBody).'"',
        'dump-header = "'.deviceHarnessConfigValue($responseHeaders).'"',
        'cookie = "'.deviceHarnessConfigValue($cookieJar).'"',
        'cookie-jar = "'.deviceHarnessConfigValue($cookieJar).'"',
        'write-out = "%{http_code}"',
        'max-time = 15',
        'header = "Accept: application/json, text/html"',
    ];

    if (! $follow) {
        $config[] = 'request = "'.$method.'"';
    }

    if ($follow) {
        $config[] = 'location';
        $config[] = 'max-redirs = 3';
    }

    if ($body !== null) {
        file_put_contents($requestBody, $body);
        chmod($requestBody, 0600);
        $config[] = 'data-binary = "@'.deviceHarnessConfigValue($requestBody).'"';
    }

    if ($contentType !== null) {
        $config[] = 'header = "Content-Type: '.deviceHarnessConfigValue($contentType).'"';
    }

    foreach ($headers as $name => $value) {
        $config[] = 'header = "'.deviceHarnessConfigValue((string) $name.': '.(string) $value).'"';
    }

    $process = new Process(['curl', '--config', '-'], timeout: 20);
    $statusOutput = deviceHarnessRun($process, 'real HTTP request', implode("\n", $config)."\n");
    $response = [
        'status' => (int) trim($statusOutput),
        'body' => (string) file_get_contents($responseBody),
        'headers' => (string) file_get_contents($responseHeaders),
    ];

    foreach ([$requestBody, $responseBody, $responseHeaders] as $path) {
        if (is_file($path)) {
            unlink($path);
        }
    }

    return $response;
}

/** @return array<string, string> */
function deviceHarnessInputs(string $html, string $action): array
{
    preg_match('/<form[^>]*>.*?name="action" value="'.preg_quote($action, '/').'".*?<\/form>/s', $html, $form);
    preg_match_all('/name="([^"]+)" value="([^"]*)"/', $form[0] ?? '', $matches, PREG_SET_ORDER);

    return array_column($matches, 2, 1);
}

function deviceHarnessCsrf(string $html): string
{
    preg_match('/name="_token" value="([^"]+)"/', $html, $match);
    $token = html_entity_decode($match[1] ?? '', ENT_QUOTES);

    return $token !== '' ? $token : failDeviceHarness('A browser context did not receive a CSRF token.');
}

/** @return array<string, mixed> */
function deviceHarnessJson(array $response, int $status): array
{
    deviceHarnessAssert($response['status'] === $status, "Expected HTTP {$status}; observed {$response['status']}.");
    $json = json_decode($response['body'], true, flags: JSON_THROW_ON_ERROR);

    return is_array($json) ? $json : failDeviceHarness('A JSON response was not an object.');
}

function deviceHarnessLogin(string $runDirectory, string $baseUrl, string $context, string $email): string
{
    $page = deviceHarnessHttp($runDirectory, $context, 'GET', $baseUrl.'/bfc/login');
    deviceHarnessAssert($page['status'] === 200, 'The disposable login page was unavailable.');
    $response = deviceHarnessHttp(
        $runDirectory,
        $context,
        'POST',
        $baseUrl.'/bfc/login',
        http_build_query([
            '_token' => deviceHarnessCsrf($page['body']),
            'email' => $email,
            'password' => 'harness owner password',
        ], '', '&', PHP_QUERY_RFC3986),
        'application/x-www-form-urlencoded',
    );
    deviceHarnessAssert($response['status'] === 302, 'The disposable browser login failed.');
    $home = deviceHarnessHttp($runDirectory, $context, 'GET', $baseUrl.'/bfc/ui');
    deviceHarnessAssert($home['status'] === 200, 'The disposable authenticated browser did not reach the package UI.');

    return deviceHarnessCsrf($home['body']);
}

/** @return array<string, mixed> */
function deviceHarnessStart(string $runDirectory, string $baseUrl, string $csrf, string $label): array
{
    $response = deviceHarnessHttp(
        $runDirectory,
        'a',
        'POST',
        $baseUrl.'/bfc/device-authorizations',
        json_encode(['app_purpose' => 'live.device', 'label' => $label], JSON_THROW_ON_ERROR),
        'application/json',
        ['X-CSRF-TOKEN' => $csrf],
    );
    $json = deviceHarnessJson($response, 201);
    deviceHarnessAssert(array_keys($json) === ['device_code', 'user_code', 'verification_uri', 'expires_in', 'interval'], 'Device start did not return the exact five-field response.');
    deviceHarnessAssert(str_contains(strtolower($response['headers']), 'cache-control: no-store'), 'Device start omitted no-store.');

    return $json;
}

function deviceHarnessUsePath(string $runDirectory, string $baseUrl, string $path, string $bearer, string $clientIdentity = 'device-live-harness'): int
{
    $requestBody = "{$runDirectory}/use-empty-body";
    file_put_contents($requestBody, '');
    chmod($requestBody, 0600);
    $config = implode("\n", [
        'silent',
        'show-error',
        'url = "'.deviceHarnessConfigValue($baseUrl.$path).'"',
        'request = "POST"',
        'header = "Accept: application/json"',
        'header = "Authorization: Bearer '.deviceHarnessConfigValue($bearer).'"',
        'header = "X-BfC-Client-Id: '.deviceHarnessConfigValue($clientIdentity).'"',
        'output = "/dev/null"',
        'write-out = "%{http_code}"',
        'max-time = 10',
    ])."\n";
    $status = (int) trim(deviceHarnessRun(new Process(['curl', '--config', '-'], timeout: 15), 'bound bearer use', $config));
    unlink($requestBody);

    return $status;
}

function deviceHarnessUse(string $runDirectory, string $baseUrl, string $profile, string $bearer, string $clientIdentity = 'device-live-harness'): int
{
    return deviceHarnessUsePath($runDirectory, $baseUrl, "/_bfc-harness/device/use/{$profile}", $bearer, $clientIdentity);
}

/** @return array<string, mixed> */
function deviceHarnessEffects(string $runDirectory, string $baseUrl, string $credentialId): array
{
    return deviceHarnessJson(deviceHarnessHttp(
        $runDirectory,
        'effects',
        'GET',
        $baseUrl.'/_bfc-harness/device/effects/'.$credentialId,
    ), 200);
}

function deviceHarnessState(string $root, array $environment, array $input): array
{
    $output = deviceHarnessRun(
        new Process([PHP_BINARY, $root.'/tests/Live/device-authorization-state.php'], $root, $environment),
        'disposable authorization state operation',
        json_encode($input, JSON_THROW_ON_ERROR),
    );
    $decoded = json_decode($output, true, flags: JSON_THROW_ON_ERROR);

    return is_array($decoded) ? $decoded : failDeviceHarness('The state helper returned an invalid shape.');
}

function deviceHarnessWaitForOutput(Process $process, string $label): string
{
    $deadline = hrtime(true) + 10_000_000_000;
    $output = '';

    do {
        $output .= $process->getIncrementalOutput();

        if (str_contains($output, "\n")) {
            return trim(strtok($output, "\n"));
        }

        if (! $process->isRunning()) {
            failDeviceHarness("{$label} exited before becoming ready.");
        }

        usleep(50_000);
    } while (hrtime(true) < $deadline);

    failDeviceHarness("{$label} missed its readiness deadline.");
}

function deviceHarnessStopServer(?Process &$server): void
{
    if ($server instanceof Process) {
        $server->stop(3, SIGTERM);
        $server = null;
    }
}

function deviceHarnessRemoveDirectory(string $directory): void
{
    if (! is_dir($directory)) {
        return;
    }

    foreach (scandir($directory) ?: [] as $entry) {
        if ($entry === '.' || $entry === '..') {
            continue;
        }

        $path = $directory.'/'.$entry;
        is_dir($path) ? deviceHarnessRemoveDirectory($path) : unlink($path);
    }

    rmdir($directory);
}

$root = dirname(__DIR__, 2);
$stampPath = $argv[1] ?? '';

if ($stampPath === '') {
    fwrite(STDERR, "usage: php tests/Live/run-device-authorization-harness.php <stamp-path>\n");
    exit(2);
}

$stampDirectory = dirname($stampPath);

if (! is_dir($stampDirectory) && ! mkdir($stampDirectory, 0777, true) && ! is_dir($stampDirectory)) {
    fwrite(STDERR, "Could not create the stamp directory.\n");
    exit(2);
}

$runDirectory = sys_get_temp_dir().'/bfc-device-authorization-'.bin2hex(random_bytes(8));
mkdir($runDirectory, 0700);
$database = $runDirectory.'/database.sqlite';
$cache = $runDirectory.'/cache';
$serverLog = $runDirectory.'/server.log';
$deviceBearerFile = $runDirectory.'/device/bearer';
$loopbackBearerFile = $runDirectory.'/loopback/bearer';
mkdir($cache, 0700);
touch($database);
touch($serverLog);
chmod($database, 0600);
chmod($serverLog, 0600);
$port = deviceHarnessPort();
$baseUrl = "http://127.0.0.1:{$port}";
$baseEnvironment = getenv();
$baseEnvironment = is_array($baseEnvironment) ? $baseEnvironment : [];
$environment = array_merge($baseEnvironment, [
    'APP_ENV' => 'testing',
    'APP_KEY' => 'base64:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=',
    'APP_URL' => $baseUrl,
    'DB_CONNECTION' => 'sqlite',
    'DB_DATABASE' => $database,
    'SESSION_DRIVER' => 'database',
    'CACHE_STORE' => 'file',
    'BFC_HARNESS_CACHE_PATH' => $cache,
    'BFC_HARNESS_DEVICE_AUTHORIZATION' => '1',
    'BUILT_FOR_CLOUD_MANAGED_CLIENT_SECRET' => 'device-live-managed-fixture-secret',
    'BUILT_FOR_CLOUD_SURFACE_DATA_MIGRATIONS' => 'false',
]);
$stamp = [
    'schema' => 'bfc.device-authorization.live.v1',
    'candidate_sha' => null,
    'runtime' => ['php' => PHP_VERSION, 'laravel' => Application::VERSION],
    'transport' => [
        'kind' => 'real-http-loopback',
        'browser_contexts' => 2,
        'isolated_cookie_jars' => true,
        'csrf_forms' => true,
        'bounded_readiness' => true,
        'bounded_teardown' => true,
    ],
    'clients' => [
        'device' => ['stdin_code' => true, 'bounded_attempts' => 180, 'bearer_mode' => '0600'],
        'loopback' => ['random_bound_port' => true, 'pkce' => 'S256', 'bearer_mode' => '0600'],
    ],
    'cases' => [],
    'secret_canaries' => ['server_log_clean' => null, 'argv_clean' => null, 'stamp_contains_secrets' => null],
    'teardown' => ['server_stopped' => false, 'run_directory_removed' => false],
    'overall_verdict' => 'fail',
    'exit_code' => 1,
];
$server = null;
$deviceClient = null;
$loopbackClient = null;
$secrets = [];
$inspectedArgv = [];

try {
    $stamp['candidate_sha'] = trim(deviceHarnessRun(new Process(['git', 'rev-parse', 'HEAD'], $root), 'candidate SHA read'));
    deviceHarnessRun(new Process([$root.'/vendor/bin/testbench', 'migrate:fresh', '--force', '--no-interaction'], $root, $environment), 'harness migration');
    deviceHarnessRun(new Process([PHP_BINARY, $root.'/tests/Live/seed-standalone-harness.php'], $root, $environment), 'harness user seed');
    $server = new Process([
        PHP_BINARY,
        '-S',
        "127.0.0.1:{$port}",
        $root.'/tests/Live/asymmetric-enrollment-server.php',
    ], $root, $environment);
    $server->setTimeout(null);
    $server->start(static function (string $type, string $output) use ($serverLog): void {
        file_put_contents($serverLog, $output, FILE_APPEND);
    });
    $deadline = hrtime(true) + 8_000_000_000;

    do {
        try {
            $ready = deviceHarnessHttp($runDirectory, 'readiness', 'GET', $baseUrl.'/bfc/meta')['status'] === 200;
        } catch (Throwable) {
            $ready = false;
        }
    } while (! $ready && $server->isRunning() && hrtime(true) < $deadline);
    deviceHarnessAssert($ready, 'The real HTTP server missed its readiness deadline.');

    $csrfA = deviceHarnessLogin($runDirectory, $baseUrl, 'a', 'owner@example.test');
    $csrfBSameUser = deviceHarnessLogin($runDirectory, $baseUrl, 'b', 'owner@example.test');
    deviceHarnessState($root, $environment, ['operation' => 'managed-authority', 'state' => 'positive']);
    $managed = deviceHarnessStart($runDirectory, $baseUrl, $csrfA, 'Live managed authority transition');
    $secrets[] = $managed['device_code'];
    $secrets[] = $managed['user_code'];
    $managedPage = deviceHarnessHttp($runDirectory, 'a', 'GET', $baseUrl.'/bfc/device');
    deviceHarnessAssert($managedPage['status'] === 200 && str_contains($managedPage['body'], $managed['user_code']), 'The managed-positive grant did not render through the package route.');
    $managedApprove = deviceHarnessInputs($managedPage['body'], 'approve');
    deviceHarnessState($root, $environment, ['operation' => 'managed-authority', 'state' => 'inactive']);
    $managedDecision = deviceHarnessHttp($runDirectory, 'a', 'POST', $baseUrl.'/bfc/device', http_build_query($managedApprove, '', '&', PHP_QUERY_RFC3986), 'application/x-www-form-urlencoded');
    $managedState = deviceHarnessState($root, $environment, [
        'operation' => 'device-decision',
        'device_code' => $managed['device_code'],
        'submission_nonce' => $managedApprove['submission_nonce'],
    ]);
    $managedCleanup = deviceHarnessHttp($runDirectory, 'a', 'GET', $baseUrl.'/bfc/device');
    deviceHarnessAssert(
        $managedDecision['status'] === 404
        && str_contains($managedDecision['body'], 'device-authorization-unavailable')
        && $managedCleanup['status'] === 404
        && ! str_contains($managedCleanup['body'], $managed['user_code'])
        && $managedState === [
            'status' => 'denied',
            'denial_reason' => 'authority_denied',
            'issued_credential_id' => null,
            'decision_events' => 1,
            'credential_count' => 0,
            'submission_nonce_present' => true,
        ],
        'The routed managed-authority denial did not preserve its terminal, nonce, credential, event, or binding invariants.',
    );
    $stamp['cases']['device_managed_authority_transition'] = [
        'decision_status' => 404,
        'denial_reason' => 'authority_denied',
        'submission_nonce_consumed' => false,
        'binding_removed' => true,
        'credential_created' => false,
    ];
    deviceHarnessState($root, $environment, ['operation' => 'managed-authority', 'state' => 'local']);

    $start = deviceHarnessStart($runDirectory, $baseUrl, $csrfA, 'Live device approval');
    $secrets[] = $start['device_code'];
    $secrets[] = $start['user_code'];
    $page = deviceHarnessHttp($runDirectory, 'a', 'GET', $baseUrl.'/bfc/device');
    deviceHarnessAssert($page['status'] === 200 && str_contains($page['body'], $start['user_code']), 'The initiating browser did not render its device grant.');
    $approve = deviceHarnessInputs($page['body'], 'approve');
    $missingNonce = $approve;
    unset($missingNonce['submission_nonce']);
    $missingNonceRefusal = deviceHarnessHttp($runDirectory, 'a', 'POST', $baseUrl.'/bfc/device', http_build_query($missingNonce, '', '&', PHP_QUERY_RFC3986), 'application/x-www-form-urlencoded');
    $tamperedNonce = $approve;
    $tamperedNonce['submission_nonce'] = str_repeat('0', 64);
    $tamperedNonceRefusal = deviceHarnessHttp($runDirectory, 'a', 'POST', $baseUrl.'/bfc/device', http_build_query($tamperedNonce, '', '&', PHP_QUERY_RFC3986), 'application/x-www-form-urlencoded');
    $afterNonceRefusals = deviceHarnessState($root, $environment, ['operation' => 'device', 'device_code' => $start['device_code']]);
    deviceHarnessAssert(
        $missingNonceRefusal['status'] === 404
        && $tamperedNonceRefusal['status'] === 404
        && ($afterNonceRefusals['status'] ?? null) === 'pending',
        'A missing or tampered submission nonce changed the device grant.',
    );
    $stamp['cases']['device_submission_nonce_refusals'] = ['missing' => 404, 'tampered' => 404, 'grant_pending' => true];
    $foreign = $approve;
    $foreign['_token'] = $csrfBSameUser;
    $sameUserRefusal = deviceHarnessHttp($runDirectory, 'b', 'POST', $baseUrl.'/bfc/device', http_build_query($foreign, '', '&', PHP_QUERY_RFC3986), 'application/x-www-form-urlencoded');
    deviceHarnessAssert($sameUserRefusal['status'] === 404, 'A same-user clean browser context reached a foreign device grant.');
    $stamp['cases']['same_user_clean_context_refusal'] = ['status' => 404, 'no_credential' => true];

    unlink($runDirectory.'/browser-b.cookies');
    $csrfBOtherUser = deviceHarnessLogin($runDirectory, $baseUrl, 'b', 'admin@example.test');
    $foreign['_token'] = $csrfBOtherUser;
    $otherUserRefusal = deviceHarnessHttp($runDirectory, 'b', 'POST', $baseUrl.'/bfc/device', http_build_query($foreign, '', '&', PHP_QUERY_RFC3986), 'application/x-www-form-urlencoded');
    deviceHarnessAssert($otherUserRefusal['status'] === 404, 'A foreign user reached the initiating browser device grant.');
    $stamp['cases']['cross_user_refusal'] = ['status' => 404, 'no_credential' => true];

    $deviceClient = new Process([$root.'/tests/Fixtures/Clients/device-client.sh', $baseUrl, $deviceBearerFile], $root, $environment);
    $deviceClient->setInput($start['device_code']."\n");
    $deviceClient->setTimeout(25);
    $deviceClient->start();
    usleep(300_000);
    $deviceCommand = $deviceClient->getCommandLine();
    $inspectedArgv[] = $deviceCommand;
    deviceHarnessAssert(! str_contains($deviceCommand, $start['device_code']), 'The device code appeared in client argv.');
    $decision = deviceHarnessHttp($runDirectory, 'a', 'POST', $baseUrl.'/bfc/device', http_build_query($approve, '', '&', PHP_QUERY_RFC3986), 'application/x-www-form-urlencoded');
    deviceHarnessAssert($decision['status'] === 200, 'The initiating browser could not approve its device grant.');
    $decisionReplay = deviceHarnessHttp($runDirectory, 'a', 'POST', $baseUrl.'/bfc/device', http_build_query($approve, '', '&', PHP_QUERY_RFC3986), 'application/x-www-form-urlencoded');
    deviceHarnessAssert($decisionReplay['status'] === 404, 'A decided device grant accepted a replayed decision.');
    $stamp['cases']['device_decision_replay_refusal'] = ['status' => 404];
    $deviceClient->wait();
    deviceHarnessAssert($deviceClient->getExitCode() === 0 && is_file($deviceBearerFile), 'The device client did not complete its bounded exchange.');
    $deviceBearer = trim((string) file_get_contents($deviceBearerFile));
    $secrets[] = $deviceBearer;
    deviceHarnessAssert((fileperms($deviceBearerFile) & 0777) === 0600, 'The device bearer file was not mode 0600.');
    deviceHarnessAssert(deviceHarnessUse($runDirectory, $baseUrl, 'device', $deviceBearer) === 200, 'The exact-bound device bearer was refused.');
    $stamp['cases']['device_approve_exchange_and_bound_use'] = ['status' => 200, 'wrong_binding_status' => 401, 'mode_0600' => true];

    $deviceCredential = deviceHarnessState($root, $environment, ['operation' => 'credential', 'flow' => 'device']);
    $credentialId = $deviceCredential['credential_id'] ?? null;
    deviceHarnessAssert(is_string($credentialId), 'The exact-bound matrix could not identify the device credential.');
    deviceHarnessState($root, $environment, ['operation' => 'reset-effects', 'credential_id' => $credentialId]);
    $beforePositiveEffects = deviceHarnessEffects($runDirectory, $baseUrl, $credentialId);
    $positiveStatus = deviceHarnessUse($runDirectory, $baseUrl, 'device', $deviceBearer, 'device-live-positive-control');
    $afterPositiveEffects = deviceHarnessEffects($runDirectory, $baseUrl, $credentialId);
    $effectCanaries = ['authorize_calls', 'limiter_attempts', 'usage_calls', 'last_used_at', 'client_identity', 'domain_handler_calls'];
    deviceHarnessAssert($positiveStatus === 200, 'The exact-bound positive control was refused.');

    foreach ($effectCanaries as $effectCanary) {
        deviceHarnessAssert(
            ($afterPositiveEffects[$effectCanary] ?? null) !== ($beforePositiveEffects[$effectCanary] ?? null),
            "The exact-bound positive control did not change {$effectCanary}.",
        );
    }

    $wrongPurposeBefore = deviceHarnessEffects($runDirectory, $baseUrl, $credentialId);
    $wrongPurposeStatus = deviceHarnessUse($runDirectory, $baseUrl, 'loopback', $deviceBearer, 'device-live-wrong-purpose');
    $wrongPurposeAfter = deviceHarnessEffects($runDirectory, $baseUrl, $credentialId);
    deviceHarnessAssert($wrongPurposeStatus === 401 && $wrongPurposeAfter === $wrongPurposeBefore, 'The wrong app-purpose refusal reached a protected-use side effect.');
    $wrongDimensions = [
        'purpose' => 'mcp',
        'subject_ref' => 'wrong-live-subject',
        'user_id' => 'first-user',
        'abilities' => ['wrong:ability'],
        'installation_ref' => 'wrong-live-installation',
        'application_ref' => 'wrong-live-application',
        'audience' => 'https://wrong-live.example',
        'algorithm' => 'RS256',
        'material_role' => 'verification_copy',
        'scope_hash' => str_repeat('0', 64),
    ];
    $matrix = [
        'valid_exact_bound' => ['status' => $positiveStatus, 'changed_effects' => $effectCanaries],
        'wrong_app_purpose' => $wrongPurposeStatus,
    ];

    foreach ($wrongDimensions as $dimension => $wrongValue) {
        $beforeEffects = deviceHarnessEffects($runDirectory, $baseUrl, $credentialId);
        deviceHarnessState($root, $environment, [
            'operation' => 'set-credential-dimension',
            'credential_id' => $credentialId,
            'dimension' => $dimension,
            'value' => $wrongValue,
        ]);
        $status = deviceHarnessUse($runDirectory, $baseUrl, 'device', $deviceBearer, 'device-live-wrong-'.$dimension);
        $afterEffects = deviceHarnessEffects($runDirectory, $baseUrl, $credentialId);
        deviceHarnessState($root, $environment, [
            'operation' => 'set-credential-dimension',
            'credential_id' => $credentialId,
            'dimension' => $dimension,
            'value' => $deviceCredential[$dimension] ?? null,
        ]);
        deviceHarnessAssert($status === 401 && $afterEffects === $beforeEffects, "The {$dimension} refusal reached a protected-use side effect.");
        $matrix[$dimension === 'scope_hash' ? 'malformed_binding' : $dimension] = $status;
    }

    $legacyBefore = deviceHarnessEffects($runDirectory, $baseUrl, $credentialId);
    $legacyStatus = deviceHarnessUsePath($runDirectory, $baseUrl, '/_bfc-harness/device/use-legacy', $deviceBearer, 'device-live-legacy-refusal');
    deviceHarnessAssert($legacyStatus === 401 && deviceHarnessEffects($runDirectory, $baseUrl, $credentialId) === $legacyBefore, 'The bound bearer entered the legacy unbound selector.');
    $matrix['bound_bearer_legacy_entry'] = $legacyStatus;
    $unbound = deviceHarnessState($root, $environment, ['operation' => 'create-unbound-bearer']);
    $unboundId = $unbound['credential_id'] ?? null;
    $unboundBearer = $unbound['access_token'] ?? null;
    deviceHarnessAssert(is_string($unboundId) && is_string($unboundBearer), 'The unbound bearer control was not created.');
    $secrets[] = $unboundBearer;
    deviceHarnessState($root, $environment, ['operation' => 'reset-effects', 'credential_id' => $unboundId]);
    $unboundBefore = deviceHarnessEffects($runDirectory, $baseUrl, $unboundId);
    $unboundStatus = deviceHarnessUse($runDirectory, $baseUrl, 'device', $unboundBearer, 'device-live-unbound-refusal');
    deviceHarnessAssert($unboundStatus === 401 && deviceHarnessEffects($runDirectory, $baseUrl, $unboundId) === $unboundBefore, 'An unbound bearer entered exact-bound protected use.');
    deviceHarnessState($root, $environment, ['operation' => 'delete-credential-control', 'credential_id' => $unboundId]);
    $matrix['unbound_bearer'] = $unboundStatus;
    $stamp['cases']['exact_bound_refusal_matrix'] = $matrix;

    $cadence = deviceHarnessStart($runDirectory, $baseUrl, $csrfA, 'Live pending and denial');
    $secrets[] = $cadence['device_code'];
    $pending = deviceHarnessJson(deviceHarnessHttp($runDirectory, 'public', 'POST', $baseUrl.'/bfc/device/token', json_encode(['device_code' => $cadence['device_code']], JSON_THROW_ON_ERROR), 'application/json'), 400);
    $slow = deviceHarnessJson(deviceHarnessHttp($runDirectory, 'public', 'POST', $baseUrl.'/bfc/device/token', json_encode(['device_code' => $cadence['device_code']], JSON_THROW_ON_ERROR), 'application/json'), 400);
    deviceHarnessAssert($pending === ['error' => 'authorization_pending'] && ($slow['error'] ?? null) === 'slow_down' && ($slow['interval'] ?? null) === 10, 'Pending and slow-down cadence did not match the frozen wire.');
    $denyPage = deviceHarnessHttp($runDirectory, 'a', 'GET', $baseUrl.'/bfc/device');
    $deny = deviceHarnessInputs($denyPage['body'], 'deny');
    deviceHarnessAssert(deviceHarnessHttp($runDirectory, 'a', 'POST', $baseUrl.'/bfc/device', http_build_query($deny, '', '&', PHP_QUERY_RFC3986), 'application/x-www-form-urlencoded')['status'] === 200, 'The device denial failed.');
    $denied = deviceHarnessJson(deviceHarnessHttp($runDirectory, 'public', 'POST', $baseUrl.'/bfc/device/token', json_encode(['device_code' => $cadence['device_code']], JSON_THROW_ON_ERROR), 'application/json'), 400);
    deviceHarnessAssert($denied === ['error' => 'access_denied'], 'The denied device grant did not return access_denied.');
    $stamp['cases']['device_pending_slow_down_and_deny'] = ['pending' => 400, 'slow_down_interval' => 10, 'denied' => 400];

    $expiring = deviceHarnessStart($runDirectory, $baseUrl, $csrfA, 'Live expiry');
    $secrets[] = $expiring['device_code'];
    deviceHarnessState($root, $environment, ['operation' => 'expire', 'device_code' => $expiring['device_code']]);
    $expired = deviceHarnessJson(deviceHarnessHttp($runDirectory, 'public-expiry', 'POST', $baseUrl.'/bfc/device/token', json_encode(['device_code' => $expiring['device_code']], JSON_THROW_ON_ERROR), 'application/json'), 400);
    deviceHarnessAssert($expired === ['error' => 'expired_token'], 'The expired device grant did not return expired_token.');
    $expiredPage = deviceHarnessHttp($runDirectory, 'a', 'GET', $baseUrl.'/bfc/device');
    deviceHarnessAssert(! str_contains($expiredPage['body'], $expiring['user_code']), 'An expired device binding remained visible in its initiating browser.');
    $stamp['cases']['device_expiry'] = ['status' => 400, 'error' => 'expired_token'];
    $stamp['cases']['device_terminal_binding_cleanup'] = ['expired_code_hidden' => true];

    $limited = deviceHarnessStart($runDirectory, $baseUrl, $csrfA, 'Live transport limiter');
    $secrets[] = $limited['device_code'];
    deviceHarnessState($root, $environment, ['operation' => 'clear-token-limiters']);
    $beforeLimit = deviceHarnessState($root, $environment, ['operation' => 'device', 'device_code' => $limited['device_code']]);

    for ($attempt = 0; $attempt < 120; $attempt++) {
        $malformed = deviceHarnessJson(deviceHarnessHttp(
            $runDirectory,
            'limiter',
            'POST',
            $baseUrl.'/bfc/device/token',
            json_encode(['unexpected' => $attempt], JSON_THROW_ON_ERROR),
            'application/json',
        ), 400);
        deviceHarnessAssert($malformed === ['error' => 'invalid_request'], 'A limiter setup request reached authorization state.');
    }

    $limitedResponse = deviceHarnessHttp($runDirectory, 'limiter', 'POST', $baseUrl.'/bfc/device/token', json_encode(['device_code' => $limited['device_code']], JSON_THROW_ON_ERROR), 'application/json');
    $limitedJson = deviceHarnessJson($limitedResponse, 429);
    $afterLimit = deviceHarnessState($root, $environment, ['operation' => 'device', 'device_code' => $limited['device_code']]);
    deviceHarnessAssert(($limitedJson['error'] ?? null) === 'slow_down' && $beforeLimit === $afterLimit, 'Transport limiter refusal changed grant cadence or authorization state.');
    $stamp['cases']['transport_limiter_refusal_before_effect'] = ['status' => 429, 'row_unchanged' => true];

    $loopbackClient = new Process([PHP_BINARY, $root.'/tests/Fixtures/Clients/loopback-client.php', $baseUrl, 'live.loopback', $loopbackBearerFile], $root, $environment);
    $loopbackClient->setTimeout(25);
    $loopbackClient->start();
    $inspectedArgv[] = $loopbackClient->getCommandLine();
    $authorizeUrl = deviceHarnessWaitForOutput($loopbackClient, 'loopback client');
    deviceHarnessAssert(! str_contains($loopbackClient->getCommandLine(), 'code_verifier'), 'Loopback proof material appeared in client argv.');
    $consent = deviceHarnessHttp($runDirectory, 'a', 'GET', $authorizeUrl);
    deviceHarnessAssert($consent['status'] === 200 && str_contains($consent['body'], 'device-authorization-loopback'), 'The loopback consent page was unavailable.');
    $loopbackApprove = deviceHarnessInputs($consent['body'], 'approve');
    $loopbackForeign = $loopbackApprove;
    $loopbackForeign['_token'] = $csrfBOtherUser;
    deviceHarnessAssert(deviceHarnessHttp($runDirectory, 'b', 'POST', $baseUrl.'/bfc/loopback/authorize', http_build_query($loopbackForeign, '', '&', PHP_QUERY_RFC3986), 'application/x-www-form-urlencoded')['status'] === 404, 'A foreign browser submitted the loopback consent.');
    $callback = deviceHarnessHttp($runDirectory, 'a', 'POST', $baseUrl.'/bfc/loopback/authorize', http_build_query($loopbackApprove, '', '&', PHP_QUERY_RFC3986), 'application/x-www-form-urlencoded', follow: true);
    deviceHarnessAssert($callback['status'] === 200, 'The exact loopback callback was not delivered.');
    $loopbackClient->wait();
    deviceHarnessAssert($loopbackClient->getExitCode() === 0 && is_file($loopbackBearerFile), 'The loopback client did not complete its PKCE exchange.');
    $loopbackBearer = trim((string) file_get_contents($loopbackBearerFile));
    $secrets[] = $loopbackBearer;
    deviceHarnessAssert((fileperms($loopbackBearerFile) & 0777) === 0600, 'The loopback bearer file was not mode 0600.');
    deviceHarnessAssert(deviceHarnessUse($runDirectory, $baseUrl, 'loopback', $loopbackBearer) === 200, 'The exact-bound loopback bearer was refused.');
    $loopbackCredential = deviceHarnessState($root, $environment, ['operation' => 'credential', 'flow' => 'loopback']);
    $loopbackCredentialId = $loopbackCredential['credential_id'] ?? null;
    deviceHarnessAssert(is_string($loopbackCredentialId), 'The loopback wrong-purpose control could not identify its credential.');
    deviceHarnessState($root, $environment, ['operation' => 'reset-effects', 'credential_id' => $loopbackCredentialId]);
    $loopbackWrongPurposeBefore = deviceHarnessEffects($runDirectory, $baseUrl, $loopbackCredentialId);
    $loopbackWrongPurposeStatus = deviceHarnessUse($runDirectory, $baseUrl, 'device', $loopbackBearer, 'loopback-live-wrong-purpose');
    $loopbackWrongPurposeAfter = deviceHarnessEffects($runDirectory, $baseUrl, $loopbackCredentialId);
    deviceHarnessAssert($loopbackWrongPurposeStatus === 401 && $loopbackWrongPurposeAfter === $loopbackWrongPurposeBefore, 'The loopback bearer crossed into the wrong bound purpose or reached a protected-use side effect.');
    $stamp['cases']['loopback_callback_pkce_and_bound_use'] = ['callback_status' => 200, 'wrong_binding_status' => $loopbackWrongPurposeStatus, 'mode_0600' => true];
    $stamp['cases']['loopback_cross_browser_refusal'] = ['status' => 404, 'no_credential' => true];

    $deniedLoopbackFile = $runDirectory.'/loopback-denied/bearer';
    $loopbackClient = new Process([PHP_BINARY, $root.'/tests/Fixtures/Clients/loopback-client.php', $baseUrl, 'live.loopback', $deniedLoopbackFile], $root, $environment);
    $loopbackClient->setTimeout(20);
    $loopbackClient->start();
    $inspectedArgv[] = $loopbackClient->getCommandLine();
    $denyUrl = deviceHarnessWaitForOutput($loopbackClient, 'denied loopback client');
    $denyConsent = deviceHarnessHttp($runDirectory, 'a', 'GET', $denyUrl);
    $loopbackDeny = deviceHarnessInputs($denyConsent['body'], 'deny');
    $denyCallback = deviceHarnessHttp($runDirectory, 'a', 'POST', $baseUrl.'/bfc/loopback/authorize', http_build_query($loopbackDeny, '', '&', PHP_QUERY_RFC3986), 'application/x-www-form-urlencoded', follow: true);
    deviceHarnessAssert($denyCallback['status'] === 400, 'The denied loopback callback was not refused by the client listener.');
    $loopbackClient->wait();
    deviceHarnessAssert($loopbackClient->getExitCode() === 1 && ! is_file($deniedLoopbackFile), 'A denied loopback grant produced a bearer.');
    $stamp['cases']['loopback_deny'] = ['callback_status' => 400, 'bearer_written' => false];

    $summary = deviceHarnessState($root, $environment, ['operation' => 'summary']);
    deviceHarnessAssert(($summary['credentials'] ?? null) === 2 && ($summary['consumed'] ?? null) === 2, 'The disposable final state did not contain exactly the two successful credentials.');
    $stamp['cases']['final_state'] = $summary;
    $stamp['overall_verdict'] = 'pass';
    $stamp['exit_code'] = 0;
} catch (Throwable $failure) {
    $stamp['failure'] = ['class' => $failure::class, 'message' => $failure->getMessage()];
} finally {
    foreach ([$deviceClient, $loopbackClient] as $client) {
        if ($client instanceof Process && $client->isRunning()) {
            $client->stop(2, SIGTERM);
        }
    }

    deviceHarnessStopServer($server);
    $serverContents = is_file($serverLog) ? (string) file_get_contents($serverLog) : '';
    $stamp['secret_canaries']['server_log_clean'] = ! deviceHarnessContainsSecret($serverContents, $secrets);
    $stamp['secret_canaries']['argv_clean'] = ! deviceHarnessContainsSecret($inspectedArgv, $secrets);

    if (! $stamp['secret_canaries']['server_log_clean'] || ! $stamp['secret_canaries']['argv_clean']) {
        $stamp['failure'] = ['class' => RuntimeException::class, 'message' => 'A ceremony secret reached a captured process surface.'];
        $stamp['overall_verdict'] = 'fail';
        $stamp['exit_code'] = 1;
    }

    $stamp['teardown']['server_stopped'] = true;
    deviceHarnessRemoveDirectory($runDirectory);
    $stamp['teardown']['run_directory_removed'] = ! is_dir($runDirectory);
    $stampContainsSecrets = deviceHarnessContainsSecret($stamp, $secrets);

    if ($stampContainsSecrets) {
        $stamp = deviceHarnessRedactSecrets($stamp, $secrets);
        $stamp['failure'] = ['class' => RuntimeException::class, 'message' => 'The stamp payload failed its secret canary and was redacted.'];
        $stamp['overall_verdict'] = 'fail';
        $stamp['exit_code'] = 1;
    }

    $stamp['secret_canaries']['stamp_contains_secrets'] = deviceHarnessContainsSecret($stamp, $secrets);
    $secrets = [];
    file_put_contents($stampPath, json_encode($stamp, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)."\n");
}

if ($stamp['exit_code'] !== 0) {
    fwrite(STDERR, 'device authorization live harness failed; stamp: '.$stampPath."\n");
    exit(1);
}

fwrite(STDOUT, 'device authorization live harness passed; stamp: '.$stampPath."\n");
