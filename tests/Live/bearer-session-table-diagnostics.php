<?php

declare(strict_types=1);
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\DB;

require __DIR__.'/../../vendor/autoload.php';

$app = require __DIR__.'/../../vendor/orchestra/testbench-core/laravel/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();

$bearer = trim((string) stream_get_contents(STDIN));

if ($bearer === '') {
    fwrite(STDOUT, 'rows=0 payload_decoded=no bearer_absent=no old_input_token_absent=no previous_url_bearer_absent=no'.PHP_EOL);
    exit(1);
}

$rows = DB::table('sessions')->get(['payload']);
$payloadDecoded = true;
$bearerAbsent = true;
$oldInputTokenAbsent = true;
$previousUrlBearerAbsent = true;

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

$passed = $payloadDecoded && $bearerAbsent && $oldInputTokenAbsent && $previousUrlBearerAbsent;

fwrite(STDOUT, sprintf(
    'rows=%d payload_decoded=%s bearer_absent=%s old_input_token_absent=%s previous_url_bearer_absent=%s%s',
    $rows->count(),
    $payloadDecoded ? 'yes' : 'no',
    $bearerAbsent ? 'yes' : 'no',
    $oldInputTokenAbsent ? 'yes' : 'no',
    $previousUrlBearerAbsent ? 'yes' : 'no',
    PHP_EOL,
));

exit($passed ? 0 : 1);
