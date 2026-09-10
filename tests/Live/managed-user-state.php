<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Contracts\Console\Kernel;

require __DIR__.'/../../vendor/autoload.php';

$app = require __DIR__.'/../../vendor/orchestra/testbench-core/laravel/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();

$user = User::query()->where('scalpels_id', 'live-subject')->sole();
$action = $argv[1] ?? 'id';

if ($action === 'expire') {
    $user->forceFill(['membership_confirmed_at' => now()->subSeconds(1800)])->save();
} elseif ($action !== 'id') {
    fwrite(STDERR, "Unknown managed user state action [{$action}].\n");
    exit(1);
}

fwrite(STDOUT, (string) $user->getKey());
