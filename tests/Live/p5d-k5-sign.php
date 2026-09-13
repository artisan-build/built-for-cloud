<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Hmac\HmacEnvelope;

require __DIR__.'/../../vendor/autoload.php';

/** @var array{key_id: string, signing_key: string, audience: string, body: string} $input */
$input = json_decode(stream_get_contents(STDIN), true, flags: JSON_THROW_ON_ERROR);
$envelope = new HmacEnvelope(
    keyId: $input['key_id'],
    eventType: 'p5d.k5.live',
    timestamp: time(),
    nonce: bin2hex(random_bytes(16)),
    audience: $input['audience'],
);

fwrite(STDOUT, $envelope->headerValue(hash_hmac(
    'sha256',
    $envelope->canonical($input['body']),
    $input['signing_key'],
)));
