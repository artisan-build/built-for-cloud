<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Tests\Support\P6HttpClient;

require __DIR__.'/../../vendor/autoload.php';

$input = json_decode((string) stream_get_contents(STDIN), true);
if (! is_array($input)
    || ! is_int($input['port'] ?? null)
    || ! is_string($input['method'] ?? null)
    || ! is_string($input['path'] ?? null)) {
    fwrite(STDERR, "Invalid P6c request worker input.\n");
    exit(2);
}

$response = (new P6HttpClient)->request(
    $input['port'],
    $input['method'],
    $input['path'],
    is_array($input['headers'] ?? null) ? $input['headers'] : [],
    is_string($input['body'] ?? null) ? $input['body'] : '',
);
fwrite(STDOUT, json_encode($response, JSON_THROW_ON_ERROR));
