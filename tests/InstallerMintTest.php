<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuditActorType;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialAuditEvent;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\LifecycleEventType;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\DetectsSecretLeaks;
use Illuminate\Console\Command;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Process;

uses(RefreshDatabase::class, DetectsSecretLeaks::class);

// Locked AC 7: the install scaffold path mints a real operator-subject
// credential printed once; no FALLBACK_TOKEN is written or read on that
// path; the deprecated command warns.

it('mints a real operator-subject credential at install time, printed once, with no fallback anywhere', function (): void {
    Process::fake();

    $envPath = $this->app->environmentFilePath();

    expect(config('built-for-cloud.fallback_token'))->toBeNull();

    $output = $this->assertNoSecretLeakageOfMinted(
        function (): string {
            expect(Artisan::call('bfc:install:operator-credential'))->toBe(Command::SUCCESS);

            return Artisan::output();
        },
        function (string $output): string {
            preg_match('/shown once: (\S+)/', $output, $matches);

            return $matches[1] ?? '';
        },
    );

    preg_match('/shown once: (\S+)/', $output, $matches);
    $secret = $matches[1];

    $this->assertRevealsSecretExactlyOnce($output, $secret);

    $credential = Credential::query()->sole();

    expect($credential->subject_type)->toBe(SubjectType::Operator)
        ->and($credential->subject_ref)->toBe('installer')
        ->and($credential->kind)->toBe(CredentialKind::Bearer)
        ->and($credential->abilities)->toBe(['admin'])
        // Revocation-on-event, never a clock: no expiry is stamped.
        ->and($credential->expires_at)->toBeNull()
        ->and($credential->secret_hash)->toBe(hash('sha256', $secret));

    // A REAL credential: it appears in the lifecycle stream…
    $event = CredentialAuditEvent::query()->where('credential_id', $credential->id)->sole();

    expect($event->event)->toBe(LifecycleEventType::Issued)
        ->and($event->actor_type)->toBe(AuditActorType::CliOperator);

    // …and it is revocable, which no env pseudo-credential ever was.
    expect(Artisan::call('bfc:credential:revoke', ['id' => $credential->id, '--local' => true]))->toBe(Command::SUCCESS)
        ->and($credential->refresh()->revoked_at)->not->toBeNull();

    // Nothing wrote a FALLBACK_TOKEN, to the env file or the config.
    expect(is_file($envPath) ? (string) file_get_contents($envPath) : '')->not->toContain('FALLBACK_TOKEN')
        ->and(config('built-for-cloud.fallback_token'))->toBeNull();

    Process::assertNothingRan();
});

it('honours a custom operator ref and abilities', function (): void {
    Artisan::call('bfc:install:operator-credential', [
        '--ref' => 'scalpels',
        '--name' => 'Scalpels control plane',
        '--abilities' => 'admin,consume',
    ]);

    $credential = Credential::query()->sole();

    expect($credential->subject_ref)->toBe('scalpels')
        ->and($credential->name)->toBe('Scalpels control plane')
        ->and($credential->abilities)->toBe(['admin', 'consume']);
});

it('warns that fallback-token:generate is deprecated while still functioning for 0.4.x apps', function (): void {
    $path = sys_get_temp_dir().'/bfc-fallback-'.bin2hex(random_bytes(6)).'/.env';
    mkdir(dirname($path));

    expect(Artisan::call('fallback-token:generate', ['--path' => $path]))->toBe(Command::SUCCESS);

    $output = Artisan::output();

    expect($output)->toContain('DEPRECATED')
        ->and($output)->toContain('bfc:install:operator-credential')
        ->and((string) file_get_contents($path))->toContain('FALLBACK_TOKEN=');
});
