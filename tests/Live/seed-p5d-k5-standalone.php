<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\User;
use ArtisanBuild\BuiltForCloud\UserRole;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Facades\Hash;

require __DIR__.'/../../vendor/autoload.php';

$app = require __DIR__.'/../../vendor/orchestra/testbench-core/laravel/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();

$owner = User::query()->create([
    'name' => 'P5d K5 Owner',
    'email' => 'p5d-k5-owner@example.test',
    'password' => Hash::make('p5d k5 owner password'),
]);
$owner->forceFill([
    'role' => UserRole::Owner->value,
    'status' => 'active',
    'email_verified_at' => now(),
    'original_contact_email' => 'p5d-k5-owner@example.test',
])->save();

$operatorBearer = 'p5d-k5-operator-'.bin2hex(random_bytes(16));
Credential::query()->create([
    'kind' => CredentialKind::Bearer,
    'subject_type' => SubjectType::Operator,
    'subject_ref' => 'p5d-k5-live-operator',
    'name' => 'p5d-k5-live-operator',
    'secret_hash' => hash('sha256', $operatorBearer),
    'status' => CredentialStatus::Active,
    'abilities' => [OperatorAbility::CredentialRotate->value],
]);

fwrite(STDOUT, $owner->getKey()."\t".$operatorBearer.PHP_EOL);
