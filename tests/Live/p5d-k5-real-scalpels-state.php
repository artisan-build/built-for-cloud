<?php

declare(strict_types=1);

use App\Models\InstallationAuthConnection;
use App\Models\Team;
use App\Models\User;
use Illuminate\Contracts\Console\Kernel;

$scalpelsRoot = $argv[1] ?? '';
$teamId = $argv[2] ?? '';
$userId = $argv[3] ?? '';
$connectionId = $argv[4] ?? '';
$action = $argv[5] ?? 'state';

require $scalpelsRoot.'/vendor/autoload.php';

$app = require $scalpelsRoot.'/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();

$team = Team::query()->findOrFail($teamId);
$user = User::query()->findOrFail($userId);
$connection = InstallationAuthConnection::query()->findOrFail($connectionId);

if ($action === 'remove') {
    $account = $team->accountFor($user);

    if ($account === null || $account->delete() !== true) {
        throw new RuntimeException('The real Scalpels membership could not be removed.');
    }
} elseif ($action !== 'state') {
    throw new RuntimeException("Unknown real Scalpels state action [{$action}].");
}

fwrite(STDOUT, json_encode([
    'membership' => $team->fresh()->accountFor($user) === null ? 'removed' : 'active',
    'roster_version' => (int) $team->fresh()->auth_roster_version,
    'response_sequence' => (int) $connection->fresh()->response_sequence,
], JSON_THROW_ON_ERROR).PHP_EOL);
