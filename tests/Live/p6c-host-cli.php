<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Actions\MintCredential;
use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyring;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\Install\ServerScaffold;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use ArtisanBuild\BuiltForCloud\MintOptions;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\Subject;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\User;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;

require __DIR__.'/vendor/autoload.php';
$app = require __DIR__.'/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();
$action = $argv[1] ?? '';
$input = json_decode((string) stream_get_contents(STDIN), true);
$input = is_array($input) ? $input : [];

if ($action === 'install') {
    $version = is_string($input['version'] ?? null) ? $input['version'] : '';
    $result = (new ServerScaffold)->install(
        __DIR__.'/.env.bfc-install',
        __DIR__.'/composer.json',
        ['BFC_P6_INSTALLED' => 'true'],
        ['artisan-build/built-for-cloud' => $version],
    );
    fwrite(STDOUT, json_encode($result->stages(), JSON_THROW_ON_ERROR));
    exit($result->succeeded() ? 0 : 1);
}

if ($action === 'seed') {
    $publicKey = is_string($input['public_key'] ?? null) ? $input['public_key'] : '';
    $password = is_string($input['password'] ?? null) ? $input['password'] : '';
    $ring = app(ConsoleKeyring::class);
    $ring->activate($ring->add('p6-live-key', $publicKey)->key_id);
    $mint = app(MintCredential::class);
    $mcp = $mint(new Subject(SubjectType::ExternalConsumer, 'p6-live-mcp'), new MintOptions(purpose: CredentialPurpose::Mcp));
    $wrong = $mint(new Subject(SubjectType::ExternalConsumer, 'p6-live-wrong-purpose'), new MintOptions(purpose: CredentialPurpose::Consumption));
    $operator = $mint(new Subject(SubjectType::Operator, 'p6-live-operator'), new MintOptions(
        purpose: CredentialPurpose::OperatorManagement,
        abilities: [OperatorAbility::Admin->value],
    ));
    $user = User::query()->create([
        'name' => 'P6 Session User',
        'email' => 'p6-session@example.test',
        'password' => Hash::make($password),
        'role' => 'admin',
        'status' => 'active',
        'email_verified_at' => now(),
    ]);

    fwrite(STDOUT, json_encode([
        'mcp_id' => $mcp->summary->id,
        'mcp_secret' => $mcp->secret?->reveal(),
        'wrong_secret' => $wrong->secret?->reveal(),
        'operator_secret' => $operator->secret?->reveal(),
        'user_id' => (string) $user->getKey(),
        'email' => $user->email,
    ], JSON_THROW_ON_ERROR));
    exit(0);
}

if ($action === 'managed') {
    DB::table('bfc_authority')->where('key', InstallationAuthority::KEY)->update([
        'mode' => AuthorityMode::Managed->value,
        'generation' => 7,
        'issuer' => 'https://p6-authority.test',
        'connection_id' => 'p6-connection',
        'organization_id' => 'p6-organization',
        'installation_id' => 'p6-installation',
        'authority_base_url' => 'https://p6-authority.test',
        'managed_connection_status' => 'active',
        'managed_connection_generation' => 7,
    ]);
    $user = User::query()->create([
        'name' => 'P6 Managed User',
        'email' => 'p6-managed@example.test',
        'role' => 'member',
        'status' => 'active',
        'scalpels_issuer' => 'https://p6-authority.test',
        'scalpels_connection_id' => 'p6-connection',
        'scalpels_id' => 'p6-managed-subject',
        'membership_confirmed_at' => now()->subMinutes(10),
        'membership_checked_at' => now()->subMinutes(10),
        'membership_response_at' => now()->subMinutes(10),
        'managed_membership_status' => 'active',
        'managed_membership_role' => 'member',
        'managed_membership_generation' => 7,
        'managed_membership_roster_version' => 1,
        'managed_membership_response_sequence' => 1,
        'managed_membership_responded_at' => now()->subMinutes(10),
    ]);
    fwrite(STDOUT, json_encode(['user_id' => (string) $user->getKey()], JSON_THROW_ON_ERROR));
    exit(0);
}

fwrite(STDERR, "Unknown P6c host action.\n");
exit(2);
