<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Contracts\UsageReporter;
use ArtisanBuild\BuiltForCloud\NullUsageReporter;
use ArtisanBuild\BuiltForCloud\TokenGenerator;

it('registers package configuration', function (): void {
    expect(config('built-for-cloud.token_prefix'))->toBe('tok_')
        ->and(config('built-for-cloud.cloud.binary'))->toBe('cloud');
});

it('binds the surviving usage reporter contract to its null implementation', function (): void {
    $reporter = app(UsageReporter::class);

    expect($reporter)->toBeInstanceOf(NullUsageReporter::class)
        ->and($reporter->perToken())->toBe([]);
});

it('generates plaintext with the configured prefix and its matching sha256 hash', function (): void {
    config(['built-for-cloud.token_prefix' => 'configured_']);

    $generated = (new TokenGenerator)->generate();

    expect($generated->plaintext)->toStartWith('configured_')
        ->and($generated->hash)->toBe(hash('sha256', $generated->plaintext));
});
