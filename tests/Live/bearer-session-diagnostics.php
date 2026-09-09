<?php

declare(strict_types=1);

use Illuminate\Contracts\Console\Kernel;
use Illuminate\Cookie\CookieValuePrefix;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\DB;

require __DIR__.'/../../vendor/autoload.php';

$app = require __DIR__.'/../../vendor/orchestra/testbench-core/laravel/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();

$bearer = trim((string) stream_get_contents(STDIN));
$cookieFile = $argv[1] ?? null;
$cookieName = (string) config('session.cookie');
$cookieValue = null;

if ($bearer === '' || ! is_string($cookieFile) || ! is_file($cookieFile)) {
    fwrite(STDOUT, 'session_found=no payload_decoded=no bearer_absent=no old_input_token_absent=no previous_url_bearer_absent=no'.PHP_EOL);
    exit(1);
}

foreach (file($cookieFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
    if (str_starts_with($line, '#') && ! str_starts_with($line, '#HttpOnly_')) {
        continue;
    }

    $fields = explode("\t", $line);

    if (($fields[5] ?? null) === $cookieName) {
        $cookieValue = rawurldecode((string) ($fields[6] ?? ''));
    }
}

$sessionId = null;

try {
    $encrypter = app('encrypter');
    $decrypted = is_string($cookieValue) ? $encrypter->decrypt($cookieValue, false) : null;
    $sessionId = is_string($decrypted)
        ? CookieValuePrefix::validate($cookieName, $decrypted, [$encrypter->getKey(), ...$encrypter->getPreviousKeys()])
        : null;
} catch (Throwable) {
    // The status output below reports an unusable cookie without exposing it.
}

$rows = DB::table('sessions')->get(['id', 'payload']);
$sessionFound = is_string($sessionId) && $rows->contains(static fn (object $row): bool => $row->id === $sessionId);
$payloadDecoded = $rows->isNotEmpty();
$bearerAbsent = $rows->isNotEmpty();
$oldInputTokenAbsent = $rows->isNotEmpty();
$previousUrlBearerAbsent = $rows->isNotEmpty();

foreach ($rows as $row) {
    $encoded = (string) $row->payload;
    $decoded = base64_decode($encoded, true);
    $payload = is_string($decoded) ? @unserialize($decoded, ['allowed_classes' => false]) : null;
    $payloadDecoded = $payloadDecoded && is_array($payload);
    $bearerAbsent = $bearerAbsent
        && is_string($decoded)
        && ! str_contains($encoded, $bearer)
        && ! str_contains($decoded, $bearer);
    $oldInputTokenAbsent = $oldInputTokenAbsent
        && is_array($payload)
        && ! Arr::has($payload, '_old_input.token');
    $previousUrl = is_array($payload) ? Arr::get($payload, '_previous.url') : null;
    $previousUrlBearerAbsent = $previousUrlBearerAbsent
        && (! is_string($previousUrl) || ! str_contains($previousUrl, $bearer));
}

$passed = $sessionFound && $payloadDecoded && $bearerAbsent && $oldInputTokenAbsent && $previousUrlBearerAbsent;

fwrite(STDOUT, sprintf(
    'session_found=%s payload_decoded=%s bearer_absent=%s old_input_token_absent=%s previous_url_bearer_absent=%s%s',
    $sessionFound ? 'yes' : 'no',
    $payloadDecoded ? 'yes' : 'no',
    $bearerAbsent ? 'yes' : 'no',
    $oldInputTokenAbsent ? 'yes' : 'no',
    $previousUrlBearerAbsent ? 'yes' : 'no',
    PHP_EOL,
));

exit($passed ? 0 : 1);
