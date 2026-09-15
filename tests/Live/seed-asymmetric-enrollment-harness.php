<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\MintCredential;
use ArtisanBuild\BuiltForCloud\BoundCredentialScope;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\MintOptions;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use Illuminate\Contracts\Console\Kernel;

require __DIR__.'/../../vendor/autoload.php';

define('TESTBENCH_WORKING_PATH', dirname(__DIR__, 2));

$app = require __DIR__.'/../../vendor/orchestra/testbench-core/laravel/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();
$scope = new BoundCredentialScope(
    'reel.application.signing',
    new Subject(SubjectType::Installation, 'reel-live-installation'),
    'install_live_1',
    'app_live_1',
    'https://reel-live.example',
);
$mint = app(MintCredential::class)(
    $scope->subject,
    new MintOptions(
        kind: CredentialKind::Asymmetric,
        purpose: CredentialPurpose::Signing,
        codeTtlSeconds: 3600,
        boundScope: $scope,
    ),
);

fwrite(STDOUT, json_encode([
    'credential_id' => $mint->summary->id,
    'enrollment_code' => $mint->secret?->reveal(),
], JSON_THROW_ON_ERROR));
