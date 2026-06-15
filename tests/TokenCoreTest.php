<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\TokenGenerator;
use ArtisanBuild\BuiltForCloud\TokenRegistry;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('resolves an empty bearer to null', function (): void {
    expect((new TokenRegistry)->resolve(''))->toBeNull();
});

it('resolves an unknown bearer to null', function (): void {
    expect((new TokenRegistry)->resolve('unknown-token'))->toBeNull();
});

it('resolves a stored active token and records usage', function (): void {
    $registry = new TokenRegistry;
    $plaintext = 'active-secret';

    $token = $registry->store('primary', hash('sha256', $plaintext));

    expect($registry->resolve($plaintext))->toBe('primary');

    $token->refresh();

    expect($token->request_count)->toBe(1)
        ->and($token->last_used_at)->not->toBeNull();
});

it('does not resolve a token expired in the past', function (): void {
    $registry = new TokenRegistry;
    $plaintext = 'past-secret';

    $registry->store('expired', hash('sha256', $plaintext), now()->subMinute());

    expect($registry->resolve($plaintext))->toBeNull();
});

it('resolves a token expiring in the future', function (): void {
    $registry = new TokenRegistry;
    $plaintext = 'future-secret';

    $registry->store('future', hash('sha256', $plaintext), now()->addMinute());

    expect($registry->resolve($plaintext))->toBe('future');
});

it('resolves the configured fallback token without database lookup', function (): void {
    config(['built-for-cloud.fallback_token' => 'fallback-secret']);

    expect((new TokenRegistry)->resolve('fallback-secret'))->toBe(TokenRegistry::FALLBACK);
});

it('does not resolve fallback when the fallback token is null', function (): void {
    config(['built-for-cloud.fallback_token' => null]);

    expect((new TokenRegistry)->resolve('fallback-secret'))->not->toBe(TokenRegistry::FALLBACK);
});

it('rejects the reserved fallback name on store', function (): void {
    (new TokenRegistry)->store(TokenRegistry::FALLBACK, hash('sha256', 'secret'));
})->throws(InvalidArgumentException::class);

it('rotates by leaving the old row resolvable for an hour by default', function (): void {
    $registry = new TokenRegistry;
    $oldPlaintext = 'old-secret';
    $newPlaintext = 'new-secret';

    $oldToken = $registry->store('rotating', hash('sha256', $oldPlaintext));
    $newToken = $registry->rotate('rotating', hash('sha256', $newPlaintext));

    $oldToken->refresh();

    expect($registry->resolve($oldPlaintext))->toBe('rotating')
        ->and($registry->resolve($newPlaintext))->toBe('rotating')
        ->and($oldToken->expires_at)->not->toBeNull()
        ->and($oldToken->expires_at?->greaterThan(now()->addMinutes(59)))->toBeTrue()
        ->and($oldToken->revoked_at)->toBeNull()
        ->and($newToken->exists)->toBeTrue();
});

it('rotates in emergency mode by expiring the old row immediately', function (): void {
    $registry = new TokenRegistry;
    $oldPlaintext = 'old-emergency-secret';
    $newPlaintext = 'new-emergency-secret';

    $oldToken = $registry->store('emergency', hash('sha256', $oldPlaintext));

    $registry->rotate('emergency', hash('sha256', $newPlaintext), emergency: true);

    $oldToken->refresh();

    expect($registry->resolve($oldPlaintext))->toBeNull()
        ->and($registry->resolve($newPlaintext))->toBe('emergency')
        ->and($oldToken->expires_at?->lessThanOrEqualTo(now()))->toBeTrue();
});

it('revokes by expiring resolvable tokens and recording revocation time', function (): void {
    $registry = new TokenRegistry;
    $plaintext = 'revoked-secret';

    $token = $registry->store('revoked', hash('sha256', $plaintext));

    expect($registry->revoke('revoked'))->toBe(1)
        ->and($registry->resolve($plaintext))->toBeNull();

    $token->refresh();

    expect($token->expires_at)->not->toBeNull()
        ->and($token->revoked_at)->not->toBeNull();
});

it('generates prefixed plaintext and matching sha256 hash', function (): void {
    config(['built-for-cloud.token_prefix' => 'bfc_']);

    $generated = (new TokenGenerator)->generate();

    expect($generated->plaintext)->toStartWith('bfc_')
        ->and($generated->hash)->toBe(hash('sha256', $generated->plaintext));
});

it('provides an api token factory with a default active token', function (): void {
    $token = ApiToken::factory()->create();

    expect($token->exists)->toBeTrue()
        ->and($token->expires_at)->toBeNull();
});
