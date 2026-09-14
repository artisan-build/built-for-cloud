<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\ClientIdentity;
use ArtisanBuild\BuiltForCloud\Tests\Support\ContractMajorLiveAuthenticationProbe;
use ArtisanBuild\BuiltForCloud\Tests\Support\ContractMajorLiveState;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Support\Facades\Route;

Route::middleware(['web', 'bfc.auth'])->get('/domain', static fn (): array => ['domain' => true]);

Route::middleware(['web', 'bfc.auth', 'bfc.admin'])->get('/managed-admin', static fn (): array => [
    'role' => request()->user()?->role,
]);

Route::middleware('bfc.hmac')->post('/_bfc-harness/p5d-hmac/{user}', static fn (): array => [
    'credential_id' => request()->attributes->get('bfc.hmac_credential_id'),
])->withoutMiddleware(PreventRequestForgery::class);

Route::middleware('auth:bfc')->get('/_bfc-harness/credential-auth', static fn (): array => [
    'authenticated' => true,
]);

Route::get('/_bfc-harness/users/{user}', static function (string $user): array {
    $account = User::query()->findOrFail($user);

    return [
        'email' => $account->email,
        'role' => $account->role,
        'status' => $account->status,
    ];
});

if (getenv('BFC_CONTRACT_MAJOR_STATE') !== false) {
    Route::post('/_bfc-harness/contract-major', static function (): array {
        ContractMajorLiveState::increment('cache_actions');
        ContractMajorLiveState::increment('queue_actions');
        ContractMajorLiveState::increment('domain_actions');

        return [
            'credential_id' => request()->user()?->getAuthIdentifier(),
            'client_id' => request()->header(ClientIdentity::HEADER),
        ];
    })->middleware([
        'bfc.contract-major',
        ContractMajorLiveAuthenticationProbe::class,
        'bfc.mcp',
    ])->withoutMiddleware(PreventRequestForgery::class);
}
