<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\MintedSecret;

function mintedSecret(): array
{
    $plaintext = 'secret_'.bin2hex(random_bytes(32));

    return [new MintedSecret($plaintext), $plaintext];
}

it('reveals the plaintext exactly once and then throws', function (): void {
    [$secret, $plaintext] = mintedSecret();

    expect($secret->revealed())->toBeFalse()
        ->and($secret->reveal())->toBe($plaintext)
        ->and($secret->revealed())->toBeTrue();

    expect(fn (): string => $secret->reveal())
        ->toThrow(LogicException::class, 'already been revealed');
});

it('exposes a stable sha256 hash before and after reveal', function (): void {
    [$secret, $plaintext] = mintedSecret();

    $expected = hash('sha256', $plaintext);

    expect($secret->hash())->toBe($expected);

    $secret->reveal();

    expect($secret->hash())->toBe($expected);
});

it('refuses php serialization', function (): void {
    [$secret] = mintedSecret();

    expect(fn (): string => serialize($secret))
        ->toThrow(LogicException::class, 'never serializes');
});

it('refuses json encoding', function (): void {
    [$secret] = mintedSecret();

    expect(fn (): string|false => json_encode($secret))
        ->toThrow(LogicException::class, 'never JSON-encodes');
});

it('refuses string conversion', function (): void {
    [$secret] = mintedSecret();

    expect(fn (): string => (string) $secret)->toThrow(Error::class);
});

it('refuses cloning', function (): void {
    [$secret] = mintedSecret();

    expect(function () use ($secret): void {
        $unused = clone $secret;
    })->toThrow(LogicException::class, 'never clones');
});

it('shows no plaintext through any export or debug path', function (): void {
    [$secret, $plaintext] = mintedSecret();

    expect(var_export($secret, true))->not->toContain($plaintext)
        ->and(print_r($secret, true))->not->toContain($plaintext);

    ob_start();
    var_dump($secret);
    $dumped = (string) ob_get_clean();

    expect($dumped)->not->toContain($plaintext)
        ->and((string) json_encode(get_object_vars($secret)))->not->toContain($plaintext);
});

it('shows no plaintext to a reflection property walk', function (): void {
    [$secret, $plaintext] = mintedSecret();

    $seen = [];

    foreach ((new ReflectionObject($secret))->getProperties() as $property) {
        $seen[$property->getName()] = $property->getValue($secret);
    }

    expect((string) json_encode($seen))->not->toContain($plaintext)
        ->and($seen)->not->toHaveKey('plaintext');
});
