<?php

declare(strict_types=1);

use App\Enums\AccountRole;
use App\ManagedAuth\Actions\CreateInstallationAuthConnection;
use App\ManagedAuth\Enums\InstallationAuthConnectionStatus;
use App\ManagedAuth\Enums\InstallationAuthMode;
use App\Models\Account;
use App\Models\Deployment;
use App\Models\InstallationAuthCredential;
use App\Models\Team;
use App\Models\User;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

$scalpelsRoot = $argv[1] ?? '';
$installationBase = $argv[2] ?? '';

require $scalpelsRoot.'/vendor/autoload.php';

$app = require $scalpelsRoot.'/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();

$owner = User::factory()->create([
    'name' => 'P5d K5 Authority Owner',
    'email' => 'p5d-k5-authority-owner@example.test',
]);
$member = User::factory()->create([
    'name' => 'P5d K5 Authority Member',
    'email' => 'p5d-k5-authority-member@example.test',
    'email_verified_at' => now(),
]);
$team = Team::factory()->create(['name' => 'P5d K5 Authority Team']);

DB::table('accounts')->insert([
    'id' => (string) Str::uuid(),
    'user_id' => $owner->getKey(),
    'team_id' => $team->getKey(),
    'role' => AccountRole::Owner->value,
    'created_at' => now(),
    'updated_at' => now(),
]);
$account = new Account;
$account->forceFill([
    'user_id' => $member->getKey(),
    'team_id' => $team->getKey(),
    'role' => AccountRole::Member,
])->save();

$deployment = Deployment::factory()->create(['team_id' => $team->getKey()]);
$connection = app(CreateInstallationAuthConnection::class)->handle(
    $deployment,
    $installationBase,
    InstallationAuthMode::Managed,
);
DB::table('installation_auth_connections')->where('id', $connection->getKey())->update([
    'authority_generation' => 2,
]);
$connection->refresh();

$secret = bin2hex(random_bytes(32));
$credential = new InstallationAuthCredential;
$credential->forceFill([
    'installation_auth_connection_id' => $connection->getKey(),
    'secret_hash' => InstallationAuthCredential::digest($secret),
    'status' => 'active',
    'activated_at' => now(),
])->save();
$connection->forceFill(['status' => InstallationAuthConnectionStatus::Active])->save();

fwrite(STDOUT, json_encode([
    'issuer' => $connection->issuer,
    'connection_id' => (string) $connection->getKey(),
    'organization_id' => (string) $team->getKey(),
    'installation_id' => (string) $deployment->getKey(),
    'generation' => $connection->authority_generation,
    'roster_version' => (int) $team->fresh()->auth_roster_version,
    'scalpels_id' => (string) $member->getKey(),
    'secret' => $secret,
], JSON_THROW_ON_ERROR).PHP_EOL);
