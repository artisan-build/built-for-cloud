<?php

declare(strict_types=1);

$port = (int) ($argv[1] ?? 0);
$certificatePath = $argv[2] ?? '';
$callbackBase = $argv[3] ?? '';
$statusPath = $argv[4] ?? '';
$clientSecret = getenv('BFC_MANAGED_FIXTURE_CLIENT_SECRET');
$authorityAppKey = getenv('BFC_MANAGED_FIXTURE_APP_KEY');
$clientAppKey = getenv('BFC_MANAGED_CLIENT_APP_KEY');

if ($port < 1
    || $certificatePath === ''
    || $callbackBase === ''
    || $statusPath === ''
    || ! is_string($clientSecret)
    || $clientSecret === ''
    || ! is_string($authorityAppKey)
    || $authorityAppKey === ''
    || $authorityAppKey === $clientAppKey) {
    fwrite(STDERR, 'Invalid managed authority fixture configuration.'.PHP_EOL);
    exit(1);
}

$privateKey = openssl_pkey_new([
    'private_key_bits' => 2048,
    'private_key_type' => OPENSSL_KEYTYPE_RSA,
]);
$request = openssl_csr_new(['commonName' => '127.0.0.1'], $privateKey, ['digest_alg' => 'sha256']);
$certificate = openssl_csr_sign($request, null, $privateKey, 1, ['digest_alg' => 'sha256']);

if ($privateKey === false || $request === false || $certificate === false) {
    fwrite(STDERR, 'Could not create the managed authority fixture certificate.'.PHP_EOL);
    exit(1);
}

openssl_x509_export($certificate, $certificatePem);
openssl_pkey_export($privateKey, $privateKeyPem);
file_put_contents($certificatePath, $certificatePem);
$keyPipe = $statusPath.'.keypipe';

if (! posix_mkfifo($keyPipe, 0600)) {
    fwrite(STDERR, 'Could not create the in-memory key pipe.'.PHP_EOL);
    exit(1);
}

$keyWriter = pcntl_fork();

if ($keyWriter === 0) {
    while (true) {
        $pipe = @fopen($keyPipe, 'wb');

        if ($pipe === false) {
            exit(0);
        }

        @fwrite($pipe, $privateKeyPem);
        fclose($pipe);
    }
}

if ($keyWriter < 0) {
    fwrite(STDERR, 'Could not start the in-memory key writer.'.PHP_EOL);
    exit(1);
}

pcntl_async_signals(true);
pcntl_signal(SIGTERM, static function () use ($keyWriter, $keyPipe): never {
    posix_kill($keyWriter, SIGTERM);
    @unlink($keyPipe);
    exit(0);
});
$context = stream_context_create([
    'ssl' => [
        'local_cert' => $certificatePath,
        'local_pk' => $keyPipe,
        'allow_self_signed' => true,
        'verify_peer' => false,
    ],
]);
$server = stream_socket_server(
    'tls://127.0.0.1:'.$port,
    $errorNumber,
    $error,
    STREAM_SERVER_BIND | STREAM_SERVER_LISTEN,
    $context,
);

if ($server === false) {
    fwrite(STDERR, 'Could not start managed authority fixture: '.$error.PHP_EOL);
    exit(1);
}

$handoffs = [];
$exchangeCount = 0;
file_put_contents($statusPath, json_encode(['exchange_count' => 0], JSON_THROW_ON_ERROR));
fwrite(STDOUT, 'READY'.PHP_EOL);
fflush(STDOUT);

while (true) {
    $connection = @stream_socket_accept($server, 30);

    if ($connection === false) {
        continue;
    }

    $raw = '';

    while (! str_contains($raw, "\r\n\r\n") && ! feof($connection)) {
        $raw .= fread($connection, 8192);
    }

    [$head, $body] = array_pad(explode("\r\n\r\n", $raw, 2), 2, '');
    $lines = explode("\r\n", $head);
    $requestLine = array_shift($lines) ?? '';
    [$method, $target] = array_pad(explode(' ', $requestLine, 3), 3, '');
    $headers = [];

    foreach ($lines as $line) {
        if (! str_contains($line, ':')) {
            continue;
        }

        [$name, $value] = explode(':', $line, 2);
        $headers[strtolower(trim($name))] = trim($value);
    }

    $length = (int) ($headers['content-length'] ?? 0);

    while (strlen($body) < $length && ! feof($connection)) {
        $body .= fread($connection, $length - strlen($body));
    }

    $path = (string) parse_url($target, PHP_URL_PATH);
    $payload = json_decode($body, true);
    $authenticated = ($headers['bfc-contract-version'] ?? null) === 'managed-auth-v1'
        && ($headers['authorization'] ?? null) === 'Bearer '.$clientSecret;

    if ($method === 'POST' && $path === '/managed-auth/v1/handoffs' && $authenticated && is_array($payload)) {
        $requestId = $payload['request_id'] ?? null;
        $valid = array_keys($payload) === ['connection_id', 'installation_id', 'request_id']
            && $payload['connection_id'] === 'live-connection'
            && $payload['installation_id'] === 'live-installation'
            && is_string($requestId)
            && $requestId !== '';

        if ($valid) {
            $handoffs[$requestId] = true;
            respond($connection, 200, [
                'contract_version' => 'managed-auth-v1',
                'request_id' => $requestId,
                'authorization_url' => 'https://127.0.0.1:'.$port.'/managed-auth/v1/authorize',
                'expires_at' => gmdate('Y-m-d\TH:i:s+00:00', time() + 90),
            ]);

            continue;
        }
    }

    if ($method === 'GET' && $path === '/managed-auth/v1/authorize') {
        parse_str((string) parse_url($target, PHP_URL_QUERY), $query);
        $state = $query['state'] ?? null;

        if (is_string($state) && isset($handoffs[$state]) && array_keys($query) === ['state']) {
            redirectTo($connection, $callbackBase.'/bfc/managed/callback?'.http_build_query([
                'state' => $state,
                'code' => 'live-code-'.bin2hex(random_bytes(8)),
            ]));

            continue;
        }
    }

    if ($method === 'POST'
        && preg_match('#^/managed-auth/v1/handoffs/([^/]+)/exchange$#', $path, $match) === 1
        && $authenticated
        && is_array($payload)) {
        $requestId = rawurldecode($match[1]);
        $valid = isset($handoffs[$requestId])
            && array_keys($payload) === ['connection_id', 'installation_id', 'code']
            && $payload['connection_id'] === 'live-connection'
            && $payload['installation_id'] === 'live-installation'
            && is_string($payload['code'])
            && $payload['code'] !== '';

        if ($valid) {
            $exchangeCount++;
            file_put_contents($statusPath, json_encode(['exchange_count' => $exchangeCount], JSON_THROW_ON_ERROR));
            respond($connection, 200, [
                'contract_version' => 'managed-auth-v1',
                'issuer' => 'https://live-issuer.example.test',
                'connection_id' => 'live-connection',
                'organization_id' => 'live-organization',
                'installation_id' => 'live-installation',
                'authority_generation' => 7,
                'roster_version' => 8,
                'response_sequence' => 13,
                'responded_at' => gmdate('Y-m-d\TH:i:s+00:00'),
                'scalpels_id' => 'live-subject',
                'membership_id' => 'live-membership',
                'membership_status' => 'active',
                'connection_status' => 'active',
                'role' => 'member',
                'display_name' => 'Live Fixture Member',
                'contact_email' => 'live-fixture@example.test',
                'contact_email_verified' => true,
            ]);

            continue;
        }
    }

    respond($connection, $authenticated ? 400 : 401, [
        'contract_version' => 'managed-auth-v1',
        'error' => $authenticated ? 'invalid_grant' : 'invalid_client',
    ]);
}

/** @param resource $connection */
function respond($connection, int $status, array $payload): void
{
    $body = json_encode($payload, JSON_THROW_ON_ERROR);
    $reason = $status === 200 ? 'OK' : ($status === 400 ? 'Bad Request' : 'Unauthorized');
    fwrite($connection, "HTTP/1.1 {$status} {$reason}\r\nContent-Type: application/json\r\nContent-Length: ".strlen($body)."\r\nConnection: close\r\n\r\n{$body}");
    fclose($connection);
}

/** @param resource $connection */
function redirectTo($connection, string $location): void
{
    fwrite($connection, "HTTP/1.1 302 Found\r\nLocation: {$location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    fclose($connection);
}
