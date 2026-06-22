<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Exceptions\InvalidInvitation;
use ArtisanBuild\BuiltForCloud\Invitation;
use ArtisanBuild\BuiltForCloud\Tests\Fixtures\User;
use Illuminate\Console\Command;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;

uses(RefreshDatabase::class);

it('augments an existing users table with an idempotent is_admin column', function (): void {
    expect(Schema::hasColumn('users', 'is_admin'))->toBeTrue();

    $user = User::query()->create([
        'name' => 'Fresh User',
        'email' => 'fresh@example.com',
        'password' => Hash::make('secret'),
    ]);

    expect($user->refresh()->is_admin)->toBeFalse();

    $migration = require __DIR__.'/../database/migrations/2026_06_22_000011_add_is_admin_to_users_table.php';
    $migration->up();

    expect(Schema::hasColumn('users', 'is_admin'))->toBeTrue();
});

it('creates the first admin and refuses another unless forced', function (): void {
    $firstExitCode = Artisan::call('create-admin', [
        '--email' => 'a@b.c',
        '--password' => 'secret-pass',
        '--name' => 'Admin',
    ]);

    $admin = User::query()->where('email', 'a@b.c')->firstOrFail();

    expect($firstExitCode)->toBe(Command::SUCCESS)
        ->and($admin->is_admin)->toBeTrue()
        ->and(Hash::check('secret-pass', $admin->password))->toBeTrue();

    $secondExitCode = Artisan::call('create-admin', [
        '--email' => 'second@b.c',
        '--password' => 'secret-pass',
        '--name' => 'Second Admin',
    ]);

    expect($secondExitCode)->toBe(Command::FAILURE)
        ->and(User::query()->where('is_admin', true)->count())->toBe(1);

    $forcedExitCode = Artisan::call('create-admin', [
        '--email' => 'forced@b.c',
        '--password' => 'secret-pass',
        '--name' => 'Forced Admin',
        '--force' => true,
    ]);

    expect($forcedExitCode)->toBe(Command::SUCCESS)
        ->and(User::query()->where('is_admin', true)->count())->toBe(2);
});

it('creates and accepts invitations exactly once', function (): void {
    $invitation = Invitation::invite('new@user.test');

    expect($invitation->token)->not->toBe('')
        ->and($invitation->expires_at?->isFuture())->toBeTrue()
        ->and(Invitation::query()->pending()->whereKey($invitation->getKey())->exists())->toBeTrue();

    $secondInvitation = Invitation::invite('another@user.test');

    expect($secondInvitation->token)->not->toBe($invitation->token);

    $user = Invitation::accept($invitation->token, [
        'name' => 'New',
        'password' => 'pw',
    ]);

    $invitation->refresh();

    expect($user)->toBeInstanceOf(User::class)
        ->and($user->email)->toBe('new@user.test')
        ->and($invitation->accepted_at)->not->toBeNull()
        ->and(User::query()->where('email', 'new@user.test')->exists())->toBeTrue();

    expect(fn () => Invitation::accept($invitation->token, ['name' => 'Again', 'password' => 'pw']))
        ->toThrow(InvalidInvitation::class);

    $expired = Invitation::factory()->create([
        'email' => 'expired@user.test',
        'expires_at' => now()->subMinute(),
    ]);

    expect(fn () => Invitation::accept($expired->token, ['name' => 'Expired', 'password' => 'pw']))
        ->toThrow(InvalidInvitation::class);

    expect(fn () => Invitation::accept('unknown-token', ['name' => 'Unknown', 'password' => 'pw']))
        ->toThrow(InvalidInvitation::class)
        ->and(User::query()->whereIn('email', ['expired@user.test', 'unknown@user.test'])->exists())->toBeFalse();
});

it('protects routes through auth and admin middleware aliases', function (): void {
    Route::middleware('bfc.auth')->get('/auth-only', fn (): string => 'auth ok');
    Route::middleware('bfc.admin')->get('/admin-only', fn (): string => 'admin ok');

    $regular = User::query()->create([
        'name' => 'Regular',
        'email' => 'regular@example.com',
        'password' => Hash::make('secret'),
    ]);

    $admin = User::query()->create([
        'name' => 'Admin',
        'email' => 'admin@example.com',
        'password' => Hash::make('secret'),
        'is_admin' => true,
    ]);

    $this->get('/auth-only')->assertUnauthorized();
    $this->get('/admin-only')->assertForbidden();
    $this->actingAs($regular)->get('/auth-only')->assertOk();
    $this->actingAs($regular)->get('/admin-only')->assertForbidden();
    $this->actingAs($admin)->get('/admin-only')->assertOk();
});
