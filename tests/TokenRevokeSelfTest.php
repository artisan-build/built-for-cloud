<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\AuditActorType;
use ArtisanBuild\BuiltForCloud\AuditReason;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\Testing\DetectsSecretLeaks;
use ArtisanBuild\BuiltForCloud\TokenRegistry;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class, DetectsSecretLeaks::class);

function mintSelfRevokable(string $name): string
{
    $plaintext = 'tok_'.bin2hex(random_bytes(32));

    ApiToken::query()->create([
        'name' => $name,
        'token_hash' => hash('sha256', $plaintext),
        'abilities' => ['consume'],
    ]);

    return $plaintext;
}

it('revokes exactly the presented credential and emits revoked with holder_request', function (): void {
    // Two credentials share the free-text name; only the PRESENTED one dies.
    $presented = mintSelfRevokable('shared-name');
    $bystander = mintSelfRevokable('shared-name');

    $presentedRow = ApiToken::query()->where('token_hash', hash('sha256', $presented))->firstOrFail();

    $this->artisan('bfc:token:revoke-self')
        ->expectsQuestion('Present the credential to revoke', $presented)
        ->expectsOutputToContain('Revoked credential '.$presentedRow->id)
        ->assertSuccessful();

    $registry = app(TokenRegistry::class);
    expect($registry->resolve($presented))->toBeNull()
        ->and($registry->resolve($bystander))->toBe('shared-name');

    $event = CredentialAuditEvent::query()
        ->where('event', LifecycleEventType::Revoked->value)
        ->where('credential_id', $presentedRow->id)
        ->firstOrFail();

    expect($event->reason_code)->toBe(AuditReason::HolderRequest)
        ->and($event->actor_type)->toBe(AuditActorType::CredentialHolder)
        ->and($event->actor_ref)->toBe($presentedRow->id);
});

it('refuses a secret passed as an argument without echoing it', function (): void {
    $plaintext = mintSelfRevokable('argv-refused');

    $this->artisan('bfc:token:revoke-self', ['secret' => $plaintext])
        ->doesntExpectOutputToContain($plaintext)
        ->expectsOutputToContain('never passed as an argument')
        ->assertFailed();

    // Refused means untouched: the credential still resolves.
    expect(app(TokenRegistry::class)->resolve($plaintext))->toBe('argv-refused');
});

it('fails closed on an unknown or dead secret without echoing it', function (): void {
    $unknown = 'tok_'.bin2hex(random_bytes(32));

    $this->artisan('bfc:token:revoke-self')
        ->expectsQuestion('Present the credential to revoke', $unknown)
        ->doesntExpectOutputToContain($unknown)
        ->expectsOutputToContain('No live credential matches')
        ->assertFailed();

    // The fallback token has no row and cannot be self-revoked.
    config()->set('built-for-cloud.fallback_token', 'fallback-secret');

    $this->artisan('bfc:token:revoke-self')
        ->expectsQuestion('Present the credential to revoke', 'fallback-secret')
        ->expectsOutputToContain('No live credential matches')
        ->assertFailed();

    expect(app(TokenRegistry::class)->resolve('fallback-secret'))->toBe(TokenRegistry::FALLBACK);
});

it('never leaks the presented secret into any observable channel', function (): void {
    $plaintext = mintSelfRevokable('leak-checked');

    $this->assertNoSecretLeakage($plaintext, function () use ($plaintext): void {
        $this->artisan('bfc:token:revoke-self')
            ->expectsQuestion('Present the credential to revoke', $plaintext)
            ->doesntExpectOutputToContain($plaintext)
            ->assertSuccessful();
    });

    // Presenting for revocation is not a use: no usage was recorded, no
    // first-use burn fired.
    $row = ApiToken::query()->where('token_hash', hash('sha256', $plaintext))->firstOrFail();
    expect($row->last_used_at)->toBeNull()
        ->and($row->request_count)->toBe(0)
        ->and($row->revoked_at)->not->toBeNull();
});
