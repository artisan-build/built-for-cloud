<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Facades\DB;

require __DIR__.'/../../vendor/autoload.php';

$app = require __DIR__.'/../../vendor/orchestra/testbench-core/laravel/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();

$action = $argv[1] ?? '';
$user = User::query()->findOrFail($argv[2] ?? '');
$credential = Credential::query()->findOrFail($argv[3] ?? '');

if ($action === 'bind') {
    $managed = InstallationAuthority::change(InstallationAuthority::current(), AuthorityMode::Managed);

    if ($managed === null || $managed->generation !== (int) ($argv[10] ?? 0)) {
        throw new RuntimeException('The package authority could not advance to the real authority generation.');
    }

    DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
        'issuer' => $argv[4],
        'connection_id' => $argv[5],
        'organization_id' => $argv[6],
        'installation_id' => $argv[7],
        'authority_base_url' => $argv[8],
        'managed_connection_status' => 'active',
    ]);
    $user->forceFill([
        'role' => 'member',
        'status' => 'active',
        'scalpels_issuer' => $argv[4],
        'scalpels_connection_id' => $argv[5],
        'scalpels_id' => $argv[9],
        'membership_confirmed_at' => now(),
        'membership_checked_at' => now(),
        'membership_response_at' => now(),
        'managed_membership_status' => 'active',
        'managed_membership_role' => 'member',
        'managed_membership_generation' => $managed->generation,
        'managed_membership_roster_version' => (int) ($argv[11] ?? 0),
        'managed_membership_response_sequence' => 0,
        'managed_membership_responded_at' => now(),
    ])->save();
} elseif ($action === 'age') {
    $seconds = filter_var($argv[4] ?? null, FILTER_VALIDATE_INT);

    if (! is_int($seconds) || $seconds < 0) {
        throw new RuntimeException('The managed age must be a non-negative integer.');
    }

    $user->forceFill(['membership_confirmed_at' => now()->subSeconds($seconds)])->save();
} elseif ($action !== 'state') {
    throw new RuntimeException("Unknown package managed state action [{$action}].");
}

$user->refresh();
$credential->refresh();
fwrite(STDOUT, json_encode([
    'authority' => InstallationAuthority::current()->mode?->value,
    'membership_status' => $user->managed_membership_status,
    'response_sequence' => $user->managed_membership_response_sequence,
    'credential_status' => $credential->status->value,
    'credential_revoked' => $credential->revoked_at === null ? 'no' : 'yes',
], JSON_THROW_ON_ERROR).PHP_EOL);
