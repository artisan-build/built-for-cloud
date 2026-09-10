<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\Invitation;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;

require __DIR__.'/../../vendor/autoload.php';

$app = require __DIR__.'/../../vendor/orchestra/testbench-core/laravel/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();

DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
    'mode' => AuthorityMode::Managed->value,
    'generation' => 7,
    'issuer' => 'https://live-issuer.example.test',
    'connection_id' => 'live-connection',
    'organization_id' => 'live-organization',
    'installation_id' => 'live-installation',
    'authority_base_url' => getenv('BFC_MANAGED_AUTHORITY_BASE_URL'),
]);
$user = User::query()->create([
    'name' => 'Live Managed Member',
    'email' => 'live-managed@example.test',
]);
$user->forceFill([
    'role' => 'member',
    'status' => 'active',
    'scalpels_issuer' => 'https://live-issuer.example.test',
    'scalpels_connection_id' => 'live-connection',
    'scalpels_id' => 'live-subject',
])->save();

$standaloneUser = User::query()->create([
    'name' => 'Live Standalone Member',
    'email' => 'live-standalone@example.test',
    'password' => Hash::make('live standalone password'),
]);
$standaloneUser->forceFill([
    'role' => UserRole::Member->value,
    'status' => 'active',
    'email_verified_at' => now(),
    'original_contact_email' => $standaloneUser->email,
])->save();

DB::table('password_reset_tokens')->insert([
    'email' => $standaloneUser->email,
    'token' => hash('sha256', 'bfc-live-sentinel'),
    'created_at' => now(),
]);
Invitation::query()->create([
    'email' => 'live-invitee@example.test',
    'token' => Invitation::hashToken('bfc-live-sentinel'),
    'role' => UserRole::Member->value,
    'expires_at' => now()->addHour(),
]);
