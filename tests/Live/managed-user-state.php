<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Facades\DB;

require __DIR__.'/../../vendor/autoload.php';

$app = require __DIR__.'/../../vendor/orchestra/testbench-core/laravel/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();

$user = User::query()->where('scalpels_id', 'live-subject')->sole();
$action = $argv[1] ?? 'id';

if ($action === 'age') {
    $seconds = filter_var($argv[2] ?? null, FILTER_VALIDATE_INT);

    if (! is_int($seconds) || $seconds < 0) {
        fwrite(STDERR, "The managed user age must be a non-negative integer.\n");
        exit(1);
    }

    $user->forceFill(['membership_confirmed_at' => now()->subSeconds($seconds)])->save();
} elseif ($action === 'mode') {
    fwrite(STDOUT, (string) DB::table('bfc_authority')
        ->where('key', InstallationAuthority::KEY)
        ->value('mode'));

    exit(0);
} elseif ($action !== 'id') {
    fwrite(STDERR, "Unknown managed user state action [{$action}].\n");
    exit(1);
}

fwrite(STDOUT, (string) $user->getKey());
