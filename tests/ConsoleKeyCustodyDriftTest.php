<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Testing\NoSigningPathScan;

/**
 * ANTI-DRIFT (carried from PR1's review). PR1's key-custody guarantee —
 * "theft of this app's whole database yields no ability to mint an
 * assertion" — rests on a claim about ABSENCE: no code path anywhere in
 * this package signs. Absence is exactly the kind of claim a later PR
 * falsifies by accident, and a docblock is not a test, so this file
 * makes the claim executable.
 *
 * The one allowed exception is matched EXACTLY:
 * `sodium_crypto_sign_ed25519_pk_to_curve25519()` converts a PUBLIC
 * signing key to a public encryption key and signs nothing. Every other
 * `sodium_crypto_sign*` call — `sodium_crypto_sign(`,
 * `sodium_crypto_sign_detached(`, `sodium_crypto_sign_keypair(` — is an
 * offence, as is any mention of paseto's `AsymmetricSecretKey`, which is
 * the signing half of the keypair this package must never hold.
 *
 * THE WALK IS TESTED, NOT ONLY THE SCANNER. A version of this file that
 * only ever ran the scanner over a CLEAN tree would pass with the
 * collection step deleted — `if ($offences !== [])` becoming
 * `if (false)` would leave it green forever, which is the worst possible
 * state for a test whose entire job is to fail in a future somebody else
 * creates. So the walk is driven over a two-file fixture containing a
 * real signing call, and the offence has to come back NAMED.
 */
it('has no signing path anywhere under src/', function (): void {
    $root = dirname(__DIR__).'/src';

    $offenders = NoSigningPathScan::scan($root);

    // A scanner that found no files would report "clean" forever.
    expect(NoSigningPathScan::countPhpFiles($root))->toBeGreaterThan(100)
        ->and($offenders)->toBe([]);
});

it('collects and names an offence when the walk meets one', function (): void {
    $root = sys_get_temp_dir().'/bfc-custody-'.bin2hex(random_bytes(6));

    mkdir($root.'/nested', 0700, true);

    file_put_contents($root.'/clean.php', "<?php\n\nfunction clean(): string { return hash('sha256', 'x'); }\n");
    file_put_contents($root.'/nested/signs.php', "<?php\n\nfunction signs(string \$m, string \$k): string { return sodium_crypto_sign(\$m, \$k); }\n");
    // Not PHP: the walk must ignore it, so a .txt full of offences
    // cannot make the test pass for the wrong reason either.
    file_put_contents($root.'/notes.txt', 'sodium_crypto_sign( AsymmetricSecretKey');

    try {
        $offenders = NoSigningPathScan::scan($root);

        expect(NoSigningPathScan::countPhpFiles($root))->toBe(2)
            ->and($offenders)->toBe(['nested/signs.php' => ['sodium_crypto_sign(']]);
    } finally {
        array_map(unlink(...), [$root.'/clean.php', $root.'/nested/signs.php', $root.'/notes.txt']);
        rmdir($root.'/nested');
        rmdir($root);
    }
});

it('would catch a signing call if one were introduced', function (string $introduced, array $expected): void {
    expect(NoSigningPathScan::offencesIn($introduced))->toBe($expected);
})->with([
    'sign' => ['$signature = sodium_crypto_sign($message, $key);', ['sodium_crypto_sign(']],
    'detached' => ['$signature = sodium_crypto_sign_detached($message, $key);', ['sodium_crypto_sign_detached(']],
    'keypair' => ['$pair = sodium_crypto_sign_keypair();', ['sodium_crypto_sign_keypair(']],
    'secret key extraction' => ['$k = sodium_crypto_sign_secretkey($pair);', ['sodium_crypto_sign_secretkey(']],
    'spaced call' => ['sodium_crypto_sign ($message, $key);', ['sodium_crypto_sign(']],
    'paseto secret key' => ['use ParagonIE\Paseto\Keys\Version4\AsymmetricSecretKey;', ['AsymmetricSecretKey']],
]);

it('matches the allowed exception precisely, and does not let a signing call ride in behind it', function (): void {
    // The exception alone: allowed.
    expect(NoSigningPathScan::offencesIn('sodium_crypto_sign_ed25519_pk_to_curve25519($publicKey);'))->toBe([]);

    // The exception PLUS a real signing call in the same file: the
    // signing call is still an offence. A check that allowed the file
    // because the exception appeared in it would be no check at all.
    expect(NoSigningPathScan::offencesIn(
        "sodium_crypto_sign_ed25519_pk_to_curve25519(\$publicKey);\nsodium_crypto_sign(\$m, \$k);",
    ))->toBe(['sodium_crypto_sign(']);

    // A name that merely STARTS like the exception is not the exception.
    expect(NoSigningPathScan::offencesIn('sodium_crypto_sign_ed25519_sk_to_curve25519($secretKey);'))
        ->toBe(['sodium_crypto_sign_ed25519_sk_to_curve25519(']);
});
