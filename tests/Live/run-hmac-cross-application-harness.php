<?php

declare(strict_types=1);

use Illuminate\Foundation\Application;
use Symfony\Component\Process\Process;

require __DIR__.'/../../vendor/autoload.php';

function hmacLiveFail(string $message): never
{
    throw new RuntimeException($message);
}

/** @param array<string, mixed> $payload @return array{status: int, body: array<string, mixed>} */
function hmacLiveRequest(int $port, string $path, array $payload): array
{
    $body = json_encode($payload, JSON_THROW_ON_ERROR);
    $context = stream_context_create(['http' => [
        'method' => 'POST',
        'header' => "Content-Type: application/json\r\nAccept: application/json\r\n",
        'content' => $body,
        'ignore_errors' => true,
        'timeout' => 5,
    ]]);
    $response = file_get_contents("http://127.0.0.1:{$port}{$path}", false, $context);
    $statusLine = $http_response_header[0] ?? '';

    if (! is_string($response) || preg_match('/\s([0-9]{3})\s/', $statusLine, $match) !== 1) {
        hmacLiveFail("Invalid response from {$path}.");
    }

    $decoded = json_decode($response, true);

    return ['status' => (int) $match[1], 'body' => is_array($decoded) ? $decoded : []];
}

/** @param array<string, string> $environment */
function hmacLiveProcess(Process $process, string $label, array $environment, ?array $input = null): string
{
    $process->setEnv($environment);

    if ($input !== null) {
        $process->setInput(json_encode($input, JSON_THROW_ON_ERROR));
    }

    if ($process->run() !== 0) {
        hmacLiveFail($label.' failed: '.$process->getErrorOutput());
    }

    return $process->getOutput();
}

function hmacLivePort(): int
{
    $socket = stream_socket_server('tcp://127.0.0.1:0', $number, $error);
    is_resource($socket) || hmacLiveFail('Could not allocate a loopback port.');
    $name = stream_socket_get_name($socket, false);
    fclose($socket);
    $port = is_string($name) ? parse_url('tcp://'.$name, PHP_URL_PORT) : false;

    return is_int($port) ? $port : hmacLiveFail('Could not read the loopback port.');
}

/** @param array<string, string> $environment */
function hmacLiveStart(string $root, int $port, array $environment, string $log): Process
{
    $server = new Process([PHP_BINARY, '-S', "127.0.0.1:{$port}", $root.'/tests/Live/hmac-cross-application-server.php'], $root, $environment);
    $server->setTimeout(null);
    $server->start(static function (string $type, string $output) use ($log): void {
        file_put_contents($log, $output, FILE_APPEND);
    });
    $deadline = hrtime(true) + 8_000_000_000;

    do {
        $ready = @file_get_contents("http://127.0.0.1:{$port}/bfc/meta") !== false;
    } while (! $ready && $server->isRunning() && hrtime(true) < $deadline);

    return $ready ? $server : hmacLiveFail('A HMAC harness server missed readiness.');
}

/** @param array<string, string> $environment @return array<string, mixed> */
function hmacLiveInspect(string $root, array $environment, array $input): array
{
    return json_decode(hmacLiveProcess(
        new Process([PHP_BINARY, $root.'/tests/Live/inspect-hmac-cross-application-harness.php'], $root),
        'HMAC harness inspection',
        $environment,
        $input,
    ), true, flags: JSON_THROW_ON_ERROR);
}

$root = dirname(__DIR__, 2);
$stampPath = $argv[1] ?? '';

if ($stampPath === '') {
    fwrite(STDERR, "usage: php tests/Live/run-hmac-cross-application-harness.php <stamp-path>\n");
    exit(2);
}

$run = sys_get_temp_dir().'/bfc-hmac-live-'.bin2hex(random_bytes(8));
mkdir($run, 0700, true);
$issuerPort = hmacLivePort();
$receiverPort = hmacLivePort();
$canary = bin2hex(random_bytes(32));
$base = getenv();
$base = is_array($base) ? $base : [];
$common = array_merge($base, [
    'APP_ENV' => 'testing',
    'APP_KEY' => 'base64:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=',
    'DB_CONNECTION' => 'sqlite',
    'SESSION_DRIVER' => 'array',
    'QUEUE_CONNECTION' => 'sync',
    'MAIL_MAILER' => 'array',
    'BUILT_FOR_CLOUD_SURFACE_DATA_MIGRATIONS' => 'false',
    'BFC_HARNESS_HMAC_CANARY' => $canary,
]);
$issuer = array_merge($common, [
    'APP_URL' => "http://127.0.0.1:{$issuerPort}",
    'DB_DATABASE' => $run.'/issuer.sqlite',
    'BFC_HARNESS_CACHE_PATH' => $run.'/issuer-cache',
    'BFC_HARNESS_HMAC_ROLE' => 'issuer',
]);
$receiver = array_merge($common, [
    'APP_URL' => "http://127.0.0.1:{$receiverPort}",
    'DB_DATABASE' => $run.'/receiver.sqlite',
    'BFC_HARNESS_CACHE_PATH' => $run.'/receiver-cache',
    'BFC_HARNESS_HMAC_ROLE' => 'receiver',
]);
$stamp = [
    'schema' => 'bfc.hmac-cross-application.loopback.v1',
    'candidate_sha' => null,
    'runtime' => ['php' => PHP_VERSION, 'laravel' => Application::VERSION],
    'stores' => ['separate_databases' => true, 'persistent_receiver_cache' => true],
    'transport' => ['kind' => 'real-http-loopback', 'issuer_port' => $issuerPort, 'receiver_port' => $receiverPort],
    'cases' => [],
    'secret_artifacts' => false,
    'overall_verdict' => 'fail',
    'exit_code' => 1,
];
$servers = [];
$claimCodes = [];

try {
    foreach ([$issuer, $receiver] as $environment) {
        touch($environment['DB_DATABASE']);
        mkdir($environment['BFC_HARNESS_CACHE_PATH'], 0700, true);
        hmacLiveProcess(new Process([$root.'/vendor/bin/testbench', 'migrate:fresh', '--force', '--no-interaction'], $root), 'HMAC database migration', $environment);
    }
    hmacLiveInspect($root, $receiver, ['mode' => 'initialize']);
    $servers[] = hmacLiveStart($root, $issuerPort, $issuer, $run.'/issuer.log');
    $servers[] = hmacLiveStart($root, $receiverPort, $receiver, $run.'/receiver.log');
    $stamp['candidate_sha'] = trim(hmacLiveProcess(new Process(['git', 'rev-parse', 'HEAD'], $root), 'candidate SHA read', $common));

    $provision = function () use ($issuerPort, $receiverPort, &$claimCodes): array {
        $mint = hmacLiveRequest($issuerPort, '/__harness/hmac/mint', []);
        $claim = $mint['body']['claim_code'] ?? null;
        is_string($claim) || hmacLiveFail('Issuer mint omitted its in-memory claim code.');
        $claimCodes[] = $claim;
        $install = hmacLiveRequest($receiverPort, '/__harness/hmac/install', [
            'claim_code' => $claim,
            'issuer_origin' => "http://127.0.0.1:{$issuerPort}",
        ]);
        $id = $install['body']['credential_id'] ?? null;
        $fingerprint = $install['body']['delivery_fingerprint'] ?? null;
        is_string($id) && is_string($fingerprint) || hmacLiveFail('Receiver installation returned an invalid shape.');
        hmacLiveRequest($issuerPort, '/__harness/hmac/activate', ['replacement_id' => $id, 'delivery_fingerprint' => $fingerprint]);

        return [$id, $claim];
    };
    [$id, $claim] = $provision();
    $replayClaim = hmacLiveRequest($receiverPort, '/__harness/hmac/install', ['claim_code' => $claim, 'issuer_origin' => "http://127.0.0.1:{$issuerPort}"]);
    $signed = hmacLiveRequest($issuerPort, '/__harness/hmac/sign', ['body' => 'callback-body', 'event' => 'matte.completed']);
    $header = (string) ($signed['body']['header'] ?? '');
    $callback = static fn (string $presentedHeader, string $body, ?string $mutation = null): array => hmacLiveRequest(
        $receiverPort,
        '/__harness/hmac/callback',
        array_filter(['header' => $presentedHeader, 'body' => $body, 'scope_mutation' => $mutation], static fn (mixed $value): bool => $value !== null),
    );
    $success = $callback($header, 'callback-body');
    $replay = $callback($header, 'callback-body');
    $stamp['cases']['success_dispatch_once'] = $success['status'] === 202 && $replay['status'] === 403;
    $stamp['cases']['claim_replay_refused'] = $replayClaim['status'] >= 400;

    foreach (['purpose', 'subject', 'installation', 'application', 'audience'] as $dimension) {
        $fresh = hmacLiveRequest($issuerPort, '/__harness/hmac/sign', ['body' => 'scope-body', 'event' => 'matte.completed']);
        $stamp['cases']['wrong_'.$dimension] = $callback((string) $fresh['body']['header'], 'scope-body', $dimension)['status'] === 403;
    }
    $stamp['cases']['unsigned'] = $callback('', 'callback-body')['status'] === 403;
    $stamp['cases']['malformed'] = $callback('not-an-envelope', 'callback-body')['status'] === 403;
    $stamp['cases']['changed_body'] = $callback($header, 'changed-body')['status'] === 403;
    $stamp['cases']['wrong_key'] = $callback(str_replace($id, '00000000-0000-4000-8000-000000000000', $header), 'callback-body')['status'] === 403;

    foreach (['revoke' => 'revoked_copy', 'expire' => 'expired_copy'] as $mutation => $label) {
        [$lifecycleId] = $provision();
        $lifecycleSigned = hmacLiveRequest($issuerPort, '/__harness/hmac/sign', ['body' => $label, 'event' => 'matte.completed']);
        hmacLiveInspect($root, $receiver, ['mode' => 'mutate', 'credential_id' => $lifecycleId, 'mutation' => $mutation]);
        $stamp['cases'][$label] = $callback((string) $lifecycleSigned['body']['header'], $label)['status'] === 403;
    }

    [$guardId] = $provision();
    $guardSigned = hmacLiveRequest($issuerPort, '/__harness/hmac/sign', ['body' => 'guard-body', 'event' => 'matte.completed']);
    $guardHeader = (string) $guardSigned['body']['header'];
    hmacLiveInspect($root, $receiver, ['mode' => 'mutate', 'credential_id' => $guardId, 'mutation' => 'poison-key-version']);
    $stamp['cases']['wrong_scope_no_effects'] = $callback($guardHeader, 'guard-body', 'installation')['status'] === 403;
    $inspection = hmacLiveInspect($root, $receiver, ['mode' => 'state', 'credential_id' => $guardId, 'header' => $guardHeader]);
    $stamp['inspection'] = $inspection;

    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($run, FilesystemIterator::SKIP_DOTS)) as $file) {
        if ($file->isFile()) {
            $bytes = file_get_contents($file->getPathname());
            $containsClaim = false;

            foreach ($claimCodes as $code) {
                $containsClaim = $containsClaim || (is_string($bytes) && str_contains($bytes, $code));
            }

            if (is_string($bytes) && (str_contains($bytes, $canary) || $containsClaim)) {
                hmacLiveFail('Plaintext HMAC or claim material reached a harness artifact.');
            }
        }
    }

    if (in_array(false, $stamp['cases'], true)
        || ($inspection['last_used'] ?? true)
        || ($inspection['rate_present'] ?? true)
        || ($inspection['nonce_present'] ?? true)
        || ! ($inspection['canary_absent_from_persistence'] ?? false)) {
        hmacLiveFail('One or more HMAC live acceptance cases failed.');
    }

    $stamp['overall_verdict'] = 'pass';
    $stamp['exit_code'] = 0;
} catch (Throwable $failure) {
    $stamp['failure'] = ['class' => $failure::class, 'message' => $failure->getMessage()];
} finally {
    foreach ($servers as $server) {
        $server->stop(3, SIGTERM);
    }
    $canary = '';
    $claimCodes = [];
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($run, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($iterator as $entry) {
        $entry->isDir() ? rmdir($entry->getPathname()) : unlink($entry->getPathname());
    }
    rmdir($run);
    is_dir(dirname($stampPath)) || mkdir(dirname($stampPath), 0777, true);
    file_put_contents($stampPath, json_encode($stamp, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)."\n");
}

exit($stamp['exit_code']);
