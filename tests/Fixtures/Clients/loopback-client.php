<?php

declare(strict_types=1);

if ($argc !== 4) {
    fwrite(STDERR, "usage: php loopback-client.php <base-url> <app-purpose> <bearer-file>\n");
    exit(2);
}

[$script, $baseUrl, $appPurpose, $bearerFile] = $argv;
$listener = stream_socket_server('tcp://127.0.0.1:0', $errorNumber, $error);

if (! is_resource($listener)) {
    fwrite(STDERR, "could not bind a loopback listener\n");
    exit(2);
}

$address = stream_socket_get_name($listener, false);
$port = is_string($address) ? parse_url('tcp://'.$address, PHP_URL_PORT) : false;

if (! is_int($port) || $port < 1024) {
    fclose($listener);
    fwrite(STDERR, "the listener did not receive an eligible port\n");
    exit(2);
}

$opaque = static fn (int $bytes): string => rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
$verifier = $opaque(64);
$state = $opaque(32);
$challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
$redirect = "http://127.0.0.1:{$port}/callback";
$authorize = rtrim($baseUrl, '/').'/bfc/loopback/authorize?'.http_build_query([
    'app_purpose' => $appPurpose,
    'redirect_uri' => $redirect,
    'code_challenge' => $challenge,
    'code_challenge_method' => 'S256',
    'state' => $state,
], '', '&', PHP_QUERY_RFC3986);

fwrite(STDOUT, $authorize."\n");
stream_set_blocking($listener, false);
$read = [$listener];
$write = null;
$except = null;

if (stream_select($read, $write, $except, 180) !== 1) {
    fclose($listener);
    fwrite(STDERR, "the callback deadline expired\n");
    exit(1);
}

$connection = stream_socket_accept($listener, 2);
fclose($listener);

if (! is_resource($connection)) {
    fwrite(STDERR, "the callback could not be accepted\n");
    exit(1);
}

stream_set_timeout($connection, 2);
$requestLine = fgets($connection, 4096);
$target = is_string($requestLine) && preg_match('/\AGET ([^ ]+) HTTP\//', $requestLine, $matches) === 1 ? $matches[1] : null;
$query = is_string($target) ? parse_url($target, PHP_URL_QUERY) : null;
parse_str(is_string($query) ? $query : '', $callback);
$valid = parse_url((string) $target, PHP_URL_PATH) === '/callback'
    && is_string($callback['state'] ?? null)
    && hash_equals($state, $callback['state'])
    && is_string($callback['code'] ?? null)
    && preg_match('/\A[A-Za-z0-9_-]{43}\z/D', $callback['code']) === 1;
$message = $valid ? 'Authorization received. You may close this window.' : 'Authorization refused.';
$status = $valid ? '200 OK' : '400 Bad Request';
fwrite($connection, "HTTP/1.1 {$status}\r\nContent-Type: text/plain\r\nCache-Control: no-store\r\nContent-Length: ".strlen($message)."\r\nConnection: close\r\n\r\n{$message}");
fclose($connection);

if (! $valid) {
    exit(1);
}

$body = json_encode([
    'code' => $callback['code'],
    'redirect_uri' => $redirect,
    'code_verifier' => $verifier,
], JSON_THROW_ON_ERROR);
$context = stream_context_create(['http' => [
    'method' => 'POST',
    'header' => "Content-Type: application/json\r\nAccept: application/json\r\nConnection: close",
    'content' => $body,
    'ignore_errors' => true,
    'timeout' => 10,
]]);
$response = file_get_contents(rtrim($baseUrl, '/').'/bfc/loopback/token', false, $context);
$json = is_string($response) ? json_decode($response, true) : null;
$accessToken = is_array($json) ? ($json['access_token'] ?? null) : null;

if (! is_string($accessToken) || $accessToken === '') {
    fwrite(STDERR, "the one-time exchange failed\n");
    exit(1);
}

$directory = dirname($bearerFile);

if (! is_dir($directory) && ! mkdir($directory, 0700, true) && ! is_dir($directory)) {
    exit(2);
}

chmod($directory, 0700);
$handle = fopen($bearerFile, 'wb');

if (! is_resource($handle)) {
    exit(2);
}

chmod($bearerFile, 0600);
fwrite($handle, $accessToken."\n");
fclose($handle);
unset($accessToken, $body, $callback, $verifier, $state);
