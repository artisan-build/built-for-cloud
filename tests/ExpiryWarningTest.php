<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\Notifications\CredentialLifecycleNotification;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\ConfigMapHolderDeclaration;
use ArtisanBuild\BuiltForCloud\TokenRegistry;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Notification;

uses(RefreshDatabase::class);

function expiringEventsFor(string $credentialId): int
{
    return CredentialAuditEvent::query()
        ->where('event', LifecycleEventType::Expiring->value)
        ->where('credential_id', $credentialId)
        ->count();
}

it('warns once, idempotently across runs, for a durable whose chosen expiry is inside the window', function (): void {
    Notification::fake();
    config()->set('built-for-cloud.credentials.declaration', ConfigMapHolderDeclaration::class);

    $registry = app(TokenRegistry::class);
    $expiringToken = $registry->store('chose-expiry', hash('sha256', 'expiring-secret'), now()->addHours(24));
    $foreverToken = $registry->store('no-expiry', hash('sha256', 'forever-secret'));

    config()->set('built-for-cloud-tests.holder_map', [
        $expiringToken->id => 'holder@example.test',
        $foreverToken->id => 'never-mailed@example.test',
    ]);

    $this->artisan('bfc:credentials:warn-expiring')
        ->expectsOutputToContain('Warned about 1 expiring credential(s).')
        ->assertSuccessful();

    // Run it again: idempotent — still exactly one event, one notification.
    $this->artisan('bfc:credentials:warn-expiring')
        ->expectsOutputToContain('Warned about 0 expiring credential(s).')
        ->assertSuccessful();

    expect(expiringEventsFor($expiringToken->id))->toBe(1)
        // A durable WITHOUT expires_at never warns: expiry is a choice,
        // and nothing here nudges anyone toward making it.
        ->and(expiringEventsFor($foreverToken->id))->toBe(0);

    Notification::assertSentOnDemandTimes(CredentialLifecycleNotification::class, 1);
    Notification::assertSentOnDemand(
        CredentialLifecycleNotification::class,
        fn (CredentialLifecycleNotification $notification, array $channels, AnonymousNotifiable $notifiable): bool => $notification->event === 'expiring'
            && ($notifiable->routes['mail'] ?? null) === 'holder@example.test',
    );

    // An extended expiry re-arms the warning for the new date. (Model
    // updates on api_tokens are allowed; only the audit table is
    // append-only.)
    ApiToken::query()->whereKey($expiringToken->id)->update(['expires_at' => now()->addHours(48)]);

    $this->artisan('bfc:credentials:warn-expiring')->assertSuccessful();

    expect(expiringEventsFor($expiringToken->id))->toBe(2);
});

it('ignores expiries outside the window until the window says otherwise', function (): void {
    Notification::fake();

    $registry = app(TokenRegistry::class);
    $farOut = $registry->store('far-out', hash('sha256', 'far-secret'), now()->addHours(100));

    $this->artisan('bfc:credentials:warn-expiring')
        ->expectsOutputToContain('Warned about 0 expiring credential(s).')
        ->assertSuccessful();

    expect(expiringEventsFor($farOut->id))->toBe(0);

    $this->artisan('bfc:credentials:warn-expiring', ['--window-hours' => 200])
        ->expectsOutputToContain('Warned about 1 expiring credential(s).')
        ->assertSuccessful();

    expect(expiringEventsFor($farOut->id))->toBe(1);
});

it('skips a credential revoked between the eligibility select and its warning transaction', function (): void {
    Notification::fake();

    $registry = app(TokenRegistry::class);
    $token = $registry->store('revoked-under-us', hash('sha256', 'race-secret'), now()->addHours(24));

    // The command has read its eligible set; before it processes this row,
    // the credential is revoked (a raw write, the way another process
    // would). The per-token transaction re-asserts eligibility and must
    // skip silently.
    $armed = true;

    DB::listen(function (QueryExecuted $query) use (&$armed, $token): void {
        if ($armed
            && preg_match('/^\s*select\b/i', $query->sql) === 1
            && str_contains($query->sql, 'api_tokens')
            && str_contains($query->sql, 'expires_at')) {
            $armed = false;

            DB::table('api_tokens')->where('id', $token->id)->update([
                'revoked_at' => now(),
                'expires_at' => now(),
            ]);
        }
    });

    $this->artisan('bfc:credentials:warn-expiring')
        ->expectsOutputToContain('Warned about 0 expiring credential(s).')
        ->assertSuccessful();

    expect($armed)->toBeFalse()
        ->and(expiringEventsFor($token->id))->toBe(0);

    Notification::assertNothingSent();
});

it('does not warn about rotation-grace rows despite their one-hour expiry', function (): void {
    Notification::fake();

    $registry = app(TokenRegistry::class);
    $old = $registry->store('graceful', hash('sha256', 'old-secret'));
    $registry->rotate('graceful', hash('sha256', 'new-secret'));

    // The old row now expires within the window — but it is a superseded
    // grace row, not a chosen expiry.
    $this->artisan('bfc:credentials:warn-expiring')
        ->expectsOutputToContain('Warned about 0 expiring credential(s).')
        ->assertSuccessful();

    expect(expiringEventsFor($old->id))->toBe(0);
});
