<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Database\Seeders\OwnerSeeder;
use ArtisanBuild\BuiltForCloud\StandaloneAccess;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Hash;

beforeEach(function (): void {
    foreach (File::allFiles(__DIR__.'/Fixtures/database/seeders') as $file) {
        require_once $file->getPathname();
    }

    $GLOBALS['bfc_fresh_seeders'] = [];
    $this->app->useDatabasePath(__DIR__.'/Fixtures/database');
});

it('migrates fresh and seeds an owner who can sign in with the documented password', function (): void {
    $exit = Artisan::call('fresh');

    $owner = User::query()->where('email', OwnerSeeder::EMAIL)->sole();

    expect($exit)->toBe(0)
        ->and(OwnerSeeder::EMAIL)->toBe('owner@example.com')
        ->and($owner->roleValue())->toBe(UserRole::Owner)
        ->and(Hash::check('password', (string) $owner->password))->toBeTrue()
        ->and($owner->hasVerifiedEmail())->toBeTrue()
        ->and(StandaloneAccess::userCanAuthenticate($owner))->toBeTrue()
        ->and(User::query()->count())->toBe(1);
});

it('wipes what was there before', function (): void {
    Artisan::call('fresh');
    User::query()->create(['name' => 'Left over', 'email' => 'left-over@example.test']);

    Artisan::call('fresh');

    expect(User::query()->pluck('email')->all())->toBe([OwnerSeeder::EMAIL]);
});

it('runs every app seeder after the owner, in class name order, skipping DatabaseSeeder and non-seeders', function (): void {
    Artisan::call('fresh');

    expect($GLOBALS['bfc_fresh_seeders'])->toBe([
        'Database\Seeders\AlphaSeeder',
        'Database\Seeders\BetaSeeder',
        'Database\Seeders\Nested\GammaSeeder',
    ]);
});

it('runs cleanly when the app has no seeders directory', function (): void {
    $this->app->useDatabasePath(__DIR__.'/Fixtures/database-without-seeders');

    expect(Artisan::call('fresh'))->toBe(0)
        ->and($GLOBALS['bfc_fresh_seeders'])->toBe([])
        ->and(User::query()->where('email', OwnerSeeder::EMAIL)->exists())->toBeTrue();
});

it('refuses to run in production and touches nothing', function (): void {
    Artisan::call('fresh');
    User::query()->create(['name' => 'Kept', 'email' => 'kept@example.test']);
    $this->app['env'] = 'production';

    try {
        $exit = Artisan::call('fresh');
        $output = Artisan::output();
    } finally {
        $this->app['env'] = 'testing';
    }

    expect($exit)->toBe(1)
        ->and($output)->toContain('refuses to run in production')
        ->and(User::query()->where('email', 'kept@example.test')->exists())->toBeTrue()
        ->and($GLOBALS['bfc_fresh_seeders'])->toHaveCount(3);
});

it('refuses when the app has prohibited destructive database commands', function (): void {
    Artisan::call('fresh');
    User::query()->create(['name' => 'Kept', 'email' => 'kept@example.test']);
    DB::prohibitDestructiveCommands();

    try {
        $exit = Artisan::call('fresh');
    } finally {
        DB::prohibitDestructiveCommands(false);
    }

    expect($exit)->toBe(1)
        ->and(User::query()->where('email', 'kept@example.test')->exists())->toBeTrue();
});
