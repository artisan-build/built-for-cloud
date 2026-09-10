<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Support\Facades\Route;

Route::middleware(['web', 'bfc.auth'])->get('/domain', static fn (): array => ['domain' => true]);

Route::middleware(['web', 'bfc.auth', 'bfc.admin'])->get('/managed-admin', static fn (): array => [
    'role' => request()->user()?->role,
]);

Route::get('/_bfc-harness/users/{user}', static function (string $user): array {
    $account = User::query()->findOrFail($user);

    return [
        'email' => $account->email,
        'role' => $account->role,
        'status' => $account->status,
    ];
});
