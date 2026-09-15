<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\CredentialKind;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\CredentialStatus;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Tests\Support\ContractMajorLiveState;
use Illuminate\Contracts\Console\Kernel;

require __DIR__.'/../../vendor/autoload.php';

define('TESTBENCH_WORKING_PATH', dirname(__DIR__, 2));

$app = require __DIR__.'/../../vendor/orchestra/testbench-core/laravel/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();

ContractMajorLiveState::reset();

$mcpSecret = 'live-mcp-'.bin2hex(random_bytes(24));
$vitalsSecret = 'live-vitals-'.bin2hex(random_bytes(24));

$mcp = Credential::query()->create([
    'kind' => CredentialKind::Bearer,
    'purpose' => CredentialPurpose::Mcp,
    'subject_type' => SubjectType::ExternalConsumer,
    'subject_ref' => 'contract-major-live-mcp',
    'secret_hash' => hash('sha256', $mcpSecret),
    'status' => CredentialStatus::Active,
]);

Credential::query()->create([
    'kind' => CredentialKind::Bearer,
    'purpose' => CredentialPurpose::DashboardMetadata,
    'subject_type' => SubjectType::Operator,
    'subject_ref' => 'contract-major-live-vitals',
    'abilities' => [OperatorAbility::MetadataRead->value],
    'secret_hash' => hash('sha256', $vitalsSecret),
    'status' => CredentialStatus::Active,
]);

fwrite(STDOUT, json_encode([
    'mcp_credential_id' => $mcp->id,
    'mcp_secret' => $mcpSecret,
    'vitals_secret' => $vitalsSecret,
], JSON_THROW_ON_ERROR));
