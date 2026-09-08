<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Facades\Hash;

require __DIR__.'/../../vendor/autoload.php';

$app = require __DIR__.'/../../vendor/orchestra/testbench-core/laravel/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();

$ids = [];

foreach ([
    ['Harness Owner', 'owner@example.test', UserRole::Owner],
    ['Harness Admin', 'admin@example.test', UserRole::Admin],
    ['Harness Member', 'member@example.test', UserRole::Member],
] as [$name, $email, $role]) {
    $user = User::query()->create([
        'name' => $name,
        'email' => $email,
        'password' => Hash::make('harness owner password'),
    ]);
    $user->forceFill([
        'role' => $role->value,
        'status' => 'active',
        'email_verified_at' => now(),
        'original_contact_email' => $email,
    ])->save();
    $ids[] = (string) $user->getKey();
}

fwrite(STDOUT, implode(' ', $ids).PHP_EOL);
