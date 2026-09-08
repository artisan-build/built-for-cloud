<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\CloudCommandRunner;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidInvitation;
use ArtisanBuild\BuiltForCloud\Invitation;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Console\Command;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;

uses(RefreshDatabase::class);

it('creates the invitations table when auth foundation invitations are enabled', function (): void {
    Schema::dropIfExists('invitations');

    $migration = require __DIR__.'/../database/migrations/2026_06_22_000010_create_invitations_table.php';
    $migration->up();

    expect(Schema::hasTable('invitations'))->toBeTrue();
});

it('skips the invitations table when auth foundation invitations are disabled', function (): void {
    config(['built-for-cloud.auth_foundation.invitations' => false]);
    Schema::dropIfExists('invitations');

    $migration = require __DIR__.'/../database/migrations/2026_06_22_000010_create_invitations_table.php';
    $migration->up();

    expect(Schema::hasTable('invitations'))->toBeFalse();
});

it('skips an existing invitations table without throwing', function (): void {
    Schema::dropIfExists('invitations');
    Schema::create('invitations', function (Blueprint $table): void {
        $table->id();
    });

    $migration = require __DIR__.'/../database/migrations/2026_06_22_000010_create_invitations_table.php';
    $migration->up();

    expect(Schema::hasTable('invitations'))->toBeTrue()
        ->and(Schema::hasColumn('invitations', 'email'))->toBeFalse();
});

it('creates the first Owner and refuses another Admin unless forced', function (): void {
    $firstExitCode = Artisan::call('create-admin', [
        '--execute' => true,
        '--email' => 'a@b.c',
        '--password' => 'secret-pass',
        '--name' => 'Admin',
    ]);

    $admin = User::query()->where('email', 'a@b.c')->firstOrFail();

    expect($firstExitCode)->toBe(Command::SUCCESS)
        ->and($admin->role)->toBe(UserRole::Owner->value)
        ->and(Hash::check('secret-pass', $admin->password))->toBeTrue();

    $secondExitCode = Artisan::call('create-admin', [
        '--execute' => true,
        '--email' => 'second@b.c',
        '--password' => 'secret-pass',
        '--name' => 'Second Admin',
    ]);

    expect($secondExitCode)->toBe(Command::FAILURE)
        ->and(User::query()->count())->toBe(1);

    $forcedExitCode = Artisan::call('create-admin', [
        '--execute' => true,
        '--email' => 'forced@b.c',
        '--password' => 'secret-pass',
        '--name' => 'Forced Admin',
        '--force' => true,
    ]);

    expect($forcedExitCode)->toBe(Command::SUCCESS)
        ->and(User::query()->where('role', UserRole::Owner->value)->count())->toBe(1)
        ->and(User::query()->where('role', UserRole::Admin->value)->count())->toBe(1);
});

it('stores the provided admin password hash verbatim in execute mode', function (): void {
    $hash = Hash::make('already-hashed');

    $exitCode = Artisan::call('create-admin', [
        '--execute' => true,
        '--email' => 'hashed@b.c',
        '--password-hash' => $hash,
        '--name' => 'Hashed Admin',
    ]);

    $admin = User::query()->where('email', 'hashed@b.c')->firstOrFail();

    expect($exitCode)->toBe(Command::SUCCESS)
        ->and($admin->password)->toBe($hash);
});

it('creates an admin locally in driver mode', function (): void {
    $exitCode = Artisan::call('create-admin', [
        '--local' => true,
        '--email' => 'local@b.c',
        '--password' => 'secret-pass',
        '--name' => 'Local Admin',
    ]);

    $admin = User::query()->where('email', 'local@b.c')->firstOrFail();

    expect($exitCode)->toBe(Command::SUCCESS)
        ->and($admin->role)->toBe(UserRole::Owner->value)
        ->and(Hash::check('secret-pass', $admin->password))->toBeTrue();
});

it('sends an escaped password hash instead of plaintext when creating an admin in cloud', function (): void {
    $runner = new class extends CloudCommandRunner
    {
        public string $environment = '';

        public string $command = '';

        /**
         * @return array{output: string, exitCode: int}
         */
        public function run(string $environment, string $artisanCommand): array
        {
            $this->environment = $environment;
            $this->command = $artisanCommand;

            return ['output' => 'Admin user cloud@example.com created.', 'exitCode' => 0];
        }
    };

    app()->instance(CloudCommandRunner::class, $runner);

    $exitCode = Artisan::call('create-admin', [
        '--environment' => 'env-1',
        '--email' => 'cloud@example.com',
        '--password' => 'secret-pass',
        '--name' => "Cloud Admin'Name",
        '--force' => true,
    ]);

    preg_match("/--password-hash='([^']+)'/", $runner->command, $matches);

    expect($exitCode)->toBe(Command::SUCCESS)
        ->and($runner->environment)->toBe('env-1')
        ->and($runner->command)->toContain('create-admin --execute')
        ->and($runner->command)->toContain('--email='.escapeshellarg('cloud@example.com'))
        ->and($runner->command)->toContain('--name='.escapeshellarg("Cloud Admin'Name"))
        ->and($matches[1] ?? null)->toBeString()
        ->and(Hash::check('secret-pass', $matches[1] ?? ''))->toBeTrue()
        ->and($runner->command)->toContain(' --force')
        ->and($runner->command)->not->toContain('--password=')
        ->and($runner->command)->not->toContain('secret-pass');
});

it('falls back to local target selection when cloud environments cannot be listed', function (): void {
    $runner = new class extends CloudCommandRunner
    {
        /**
         * @return array<string, string>
         */
        public function listEnvironments(): array
        {
            return [];
        }
    };

    app()->instance(CloudCommandRunner::class, $runner);

    $exitCode = Artisan::call('create-admin', [
        '--email' => 'fallback@b.c',
        '--password' => 'secret-pass',
        '--name' => 'Fallback Admin',
    ]);

    expect($exitCode)->toBe(Command::SUCCESS)
        ->and(Artisan::output())->toContain('only local creation is available')
        ->and(User::query()->where('email', 'fallback@b.c')->where('role', UserRole::Owner->value)->exists())->toBeTrue();
});

it('fails create-admin clearly when the role column is missing', function (): void {
    Schema::table('users', function (Blueprint $table): void {
        $table->dropUnique('users_owner_slot_unique');
    });

    Schema::table('users', function (Blueprint $table): void {
        $table->dropColumn(['owner_slot', 'role']);
    });

    $exitCode = Artisan::call('create-admin', [
        '--execute' => true,
        '--email' => 'missing@b.c',
        '--password' => 'secret-pass',
        '--name' => 'Missing Column',
    ]);

    expect($exitCode)->toBe(Command::FAILURE)
        ->and(Artisan::output())->toContain('The role column is missing - run your migrations first.')
        ->and(User::query()->where('email', 'missing@b.c')->exists())->toBeFalse();
});

it('creates and accepts invitations exactly once', function (): void {
    // PR8's documented break (release-notes/invitations-convergence.md):
    // the ttl is REQUIRED — the old 7-day default is gone.
    $invitation = Invitation::invite('new@user.test', 604800);
    $plainTextToken = $invitation->token;
    $tokenHash = hash('sha256', $plainTextToken);

    expect($plainTextToken)->not->toBe('')
        ->and($invitation->expires_at?->isFuture())->toBeTrue()
        ->and(Invitation::query()->pending()->whereKey($invitation->getKey())->exists())->toBeTrue()
        ->and(Invitation::query()->whereKey($invitation->getKey())->value('token'))->toBe($tokenHash)
        ->and(Invitation::query()->whereKey($invitation->getKey())->value('token'))->not->toBe($plainTextToken);

    $secondInvitation = Invitation::invite('another@user.test', 604800);

    expect($secondInvitation->token)->not->toBe($plainTextToken);

    $user = Invitation::accept($plainTextToken, [
        'name' => 'New',
        'password' => 'pw',
    ]);

    $invitation->refresh();

    expect($user)->toBeInstanceOf(User::class)
        ->and($user->email)->toBe('new@user.test')
        ->and($invitation->accepted_at)->not->toBeNull()
        ->and(User::query()->where('email', 'new@user.test')->exists())->toBeTrue();

    expect(fn () => Invitation::accept($plainTextToken, ['name' => 'Again', 'password' => 'pw']))
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

it('ignores role escalation attempts while accepting invitations', function (): void {
    $invitation = Invitation::invite('mallory@user.test', 604800);

    $user = Invitation::accept($invitation->token, [
        'name' => 'Mallory',
        'password' => 'pw',
        'role' => UserRole::Owner->value,
    ]);

    expect($user)->toBeInstanceOf(User::class)
        ->and($user->refresh()->role)->toBe(UserRole::Member->value)
        ->and($user->email)->toBe('mallory@user.test');
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
    ]);

    $admin->forceFill(['role' => UserRole::Admin->value])->save();

    $this->get('/auth-only')->assertUnauthorized();
    $this->get('/admin-only')->assertForbidden();
    $this->actingAs($regular)->get('/auth-only')->assertOk();
    $this->actingAs($regular)->get('/admin-only')->assertForbidden();

    DB::table('users')->where('id', $regular->getKey())->update(['role' => 'super-admin']);
    $regular->refresh();

    $this->actingAs($regular)->get('/auth-only')->assertForbidden();

    DB::table('users')->where('id', $regular->getKey())->update([
        'role' => UserRole::Member->value,
        'status' => 'inactive',
    ]);
    $regular->refresh();

    $this->actingAs($regular)->get('/auth-only')->assertForbidden();
    $this->actingAs($admin)->get('/admin-only')->assertOk();
});
