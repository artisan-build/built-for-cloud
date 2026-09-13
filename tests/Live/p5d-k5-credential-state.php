<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Credential;
use Illuminate\Contracts\Console\Kernel;

require __DIR__.'/../../vendor/autoload.php';

$app = require __DIR__.'/../../vendor/orchestra/testbench-core/laravel/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();

$credential = Credential::query()->findOrFail($argv[1] ?? '');

fwrite(STDOUT, implode(' ', [
    'kind='.$credential->kind->value,
    'subject='.$credential->subject_ref,
    'user='.$credential->user_id,
    'status='.$credential->status->value,
    'delivered='.($credential->delivered_at === null ? 'no' : 'yes'),
    'activated='.($credential->activated_at === null ? 'no' : 'yes'),
]).PHP_EOL);
