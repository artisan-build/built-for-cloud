<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Facades\DB;

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
