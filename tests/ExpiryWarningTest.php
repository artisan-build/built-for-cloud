<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\Notifications\CredentialLifecycleNotification;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\ConfigMapHolderDeclaration;
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

    $expiringCredential = Credential::factory()->create(['expires_at' => now()->addHours(24)]);
    $foreverCredential = Credential::factory()->create(['expires_at' => null]);
    $pendingCredential = Credential::factory()->pending()->create(['expires_at' => now()->addHours(24)]);
    $revokedCredential = Credential::factory()->revoked()->create(['expires_at' => now()->addHours(24)]);
    config()->set('built-for-cloud-tests.holder_map', [
        $expiringCredential->id => 'holder@example.test',
        $foreverCredential->id => 'never-mailed@example.test',
        $pendingCredential->id => 'pending@example.test',
        $revokedCredential->id => 'revoked@example.test',
    ]);

    $this->artisan('bfc:credentials:warn-expiring')
        ->expectsOutputToContain('Warned about 1 expiring credential(s).')
        ->assertSuccessful();

    // Run it again: idempotent — still exactly one event, one notification.
    $this->artisan('bfc:credentials:warn-expiring')
        ->expectsOutputToContain('Warned about 0 expiring credential(s).')
        ->assertSuccessful();

    expect(expiringEventsFor($expiringCredential->id))->toBe(1)
        // A durable WITHOUT expires_at never warns: expiry is a choice,
        // and nothing here nudges anyone toward making it.
        ->and(expiringEventsFor($foreverCredential->id))->toBe(0)
        ->and(expiringEventsFor($pendingCredential->id))->toBe(0)
        ->and(expiringEventsFor($revokedCredential->id))->toBe(0);

    Notification::assertSentOnDemandTimes(CredentialLifecycleNotification::class, 1);
    Notification::assertSentOnDemand(
        CredentialLifecycleNotification::class,
        fn (CredentialLifecycleNotification $notification, array $channels, AnonymousNotifiable $notifiable): bool => $notification->event === 'expiring'
            && ($notifiable->routes['mail'] ?? null) === 'holder@example.test',
    );

    // An extended expiry re-arms the warning for the new date.
    Credential::query()->whereKey($expiringCredential->id)->update(['expires_at' => now()->addHours(48)]);

    $this->artisan('bfc:credentials:warn-expiring')->assertSuccessful();

    expect(expiringEventsFor($expiringCredential->id))->toBe(2);
});

it('ignores expiries outside the window until the window says otherwise', function (): void {
    Notification::fake();

    $farOut = Credential::factory()->create(['expires_at' => now()->addHours(100)]);

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

    $credential = Credential::factory()->create(['expires_at' => now()->addHours(24)]);

    // The command has read its eligible set; before it processes this row,
    // the credential is revoked (a raw write, the way another process
    // would). The per-token transaction re-asserts eligibility and must
    // skip silently.
    $armed = true;

    DB::listen(function (QueryExecuted $query) use (&$armed, $credential): void {
        if ($armed
            && preg_match('/^\s*select\b/i', $query->sql) === 1
            && str_contains($query->sql, 'credentials')
            && str_contains($query->sql, 'expires_at')) {
            $armed = false;

            DB::table('credentials')->where('id', $credential->id)->update([
                'revoked_at' => now(),
            ]);
        }
    });

    $this->artisan('bfc:credentials:warn-expiring')
        ->expectsOutputToContain('Warned about 0 expiring credential(s).')
        ->assertSuccessful();

    expect($armed)->toBeFalse()
        ->and(expiringEventsFor($credential->id))->toBe(0);

    Notification::assertNothingSent();
});

it('does not warn about rotation-grace rows despite their one-hour expiry', function (): void {
    Notification::fake();

    $old = Credential::factory()->create(['expires_at' => now()->addHour()]);
    Credential::query()->whereKey($old->id)->update(['rotated_at' => now()]);

    // The old row now expires within the window — but it is a superseded
    // grace row, not a chosen expiry.
    $this->artisan('bfc:credentials:warn-expiring')
        ->expectsOutputToContain('Warned about 0 expiring credential(s).')
        ->assertSuccessful();

    expect(expiringEventsFor($old->id))->toBe(0);
});
