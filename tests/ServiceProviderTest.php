<?php

declare(strict_types=1);

it('registers package configuration', function (): void {
    expect(config('built-for-cloud.token_prefix'))->toBe('tok_')
        ->and(config('built-for-cloud.cloud.binary'))->toBe('cloud');
});

it('disables the fallback token by default', function (): void {
    expect(config('built-for-cloud.fallback_token'))->toBeNull();
});
