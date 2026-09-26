<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\BuiltForCloud;
use ArtisanBuild\BuiltForCloud\Console\AssertionBurn;
use ArtisanBuild\BuiltForCloud\Console\AssertionPurpose;
use ArtisanBuild\BuiltForCloud\Console\AssertionVerifier;
use ArtisanBuild\BuiltForCloud\Console\ConsoleKeyring;
use ArtisanBuild\BuiltForCloud\Console\ConsoleRole;
use ArtisanBuild\BuiltForCloud\Mcp\Classification;
use ArtisanBuild\BuiltForCloud\MetadataShape;
use ArtisanBuild\BuiltForCloud\OwnershipClaim;
use ArtisanBuild\BuiltForCloud\Vitals\VitalsPayload;
use ArtisanBuild\BuiltForCloudContracts\BuiltForCloud as ContractsBuiltForCloud;
use ArtisanBuild\BuiltForCloudContracts\Console\AssertionBurn as ContractsAssertionBurn;
use ArtisanBuild\BuiltForCloudContracts\Console\AssertionPurpose as ContractsAssertionPurpose;
use ArtisanBuild\BuiltForCloudContracts\Console\AssertionVerifier as ContractsAssertionVerifier;
use ArtisanBuild\BuiltForCloudContracts\Console\ConsoleKeyring as ContractsConsoleKeyring;
use ArtisanBuild\BuiltForCloudContracts\Console\ConsoleRole as ContractsConsoleRole;
use ArtisanBuild\BuiltForCloudContracts\Mcp\Classification as ContractsClassification;
use ArtisanBuild\BuiltForCloudContracts\MetadataShape as ContractsMetadataShape;
use ArtisanBuild\BuiltForCloudContracts\OwnershipClaim as ContractsOwnershipClaim;
use ArtisanBuild\BuiltForCloudContracts\Vitals\VitalsPayload as ContractsVitalsPayload;
use Composer\InstalledVersions;
use Illuminate\Database\Eloquent\Model;

it('installs contracts v0.1.0 and keeps the release and protocol versions distinct', function (): void {
    expect(InstalledVersions::getPrettyVersion('artisan-build/built-for-cloud-contracts'))->toBe('v0.1.0')
        ->and(BuiltForCloud::VERSION)->toBe('0.17.0')
        ->and(BuiltForCloud::API_VERSION)->toBe(ContractsBuiltForCloud::API_VERSION)
        ->and(BuiltForCloud::API_VERSION)->toBe(2);
});

it('keeps the complete ordered enum vocabularies compatible', function (): void {
    $map = static fn (array $cases): array => array_column(array_map(
        static fn (BackedEnum $case): array => ['name' => $case->name, 'value' => $case->value],
        $cases,
    ), 'value', 'name');

    expect($map(Classification::cases()))->toBe($map(ContractsClassification::cases()))
        ->and($map(Classification::cases()))->toBe(['Metadata' => 'metadata', 'Content' => 'content'])
        ->and($map(ConsoleRole::cases()))->toBe($map(ContractsConsoleRole::cases()))
        ->and($map(ConsoleRole::cases()))->toBe(['Admin' => 'admin', 'Member' => 'member'])
        ->and(ConsoleRole::values())->toBe(ContractsConsoleRole::values())
        ->and(ConsoleRole::values())->toBe(['admin', 'member'])
        ->and($map(AssertionPurpose::cases()))->toBe($map(ContractsAssertionPurpose::cases()))
        ->and($map(AssertionPurpose::cases()))->toBe(['ConsoleEntry' => 'console-entry', 'Mcp' => 'mcp']);
});

it('keeps every extracted contract constant exact', function (): void {
    expect(ConsoleKeyring::PUBLIC_KEY_BYTES)->toBe(ContractsConsoleKeyring::PUBLIC_KEY_BYTES)->toBe(32)
        ->and(ConsoleKeyring::KEY_ID_PATTERN)->toBe(ContractsConsoleKeyring::KEY_ID_PATTERN)->toBe('/^[A-Za-z0-9._-]{1,64}\z/')
        ->and(AssertionVerifier::HEADER)->toBe(ContractsAssertionVerifier::HEADER)->toBe('v4.public.')
        ->and(AssertionVerifier::MAX_DISPLAY_LENGTH)->toBe(ContractsAssertionVerifier::MAX_DISPLAY_LENGTH)->toBe(120)
        ->and(AssertionVerifier::MAX_IDENTITY_LENGTH)->toBe(ContractsAssertionVerifier::MAX_IDENTITY_LENGTH)->toBe(255)
        ->and(AssertionVerifier::MAX_ID_LENGTH)->toBe(ContractsAssertionVerifier::MAX_ID_LENGTH)->toBe(64)
        ->and(AssertionVerifier::STATE_DIGEST_PATTERN)->toBe(ContractsAssertionVerifier::STATE_DIGEST_PATTERN)->toBe('/^[0-9a-f]{64}\z/')
        ->and(AssertionVerifier::MAX_TOKEN_LENGTH)->toBe(ContractsAssertionVerifier::MAX_TOKEN_LENGTH)->toBe(4096)
        ->and(AssertionBurn::PRUNE_MARGIN_SECONDS)->toBe(ContractsAssertionBurn::PRUNE_MARGIN_SECONDS)->toBe(60)
        ->and(VitalsPayload::VERSION)->toBe(ContractsVitalsPayload::VERSION)->toBe(1)
        ->and(VitalsPayload::MAX_HEADLINE_MAGNITUDE)->toBe(ContractsVitalsPayload::MAX_HEADLINE_MAGNITUDE)->toBe(1.0e15)
        ->and(VitalsPayload::MAX_AGE_SECONDS)->toBe(ContractsVitalsPayload::MAX_AGE_SECONDS)->toBe(3153600000)
        ->and(MetadataShape::TOKEN)->toBe(ContractsMetadataShape::TOKEN)->toBe('/^(?=.{1,64}$)[a-z0-9]+(?:[._:-][a-z0-9]+)*$/D')
        ->and(MetadataShape::SEMVER)->toBe(ContractsMetadataShape::SEMVER)->toBe('/^(?=.{1,32}$)\d{1,6}\.\d{1,6}\.\d{1,6}(?:-[0-9a-z]+(?:[.-][0-9a-z]+)*)?(?:\+[0-9a-z]+(?:[.-][0-9a-z]+)*)?$/D')
        ->and(MetadataShape::TIMESTAMP)->toBe(ContractsMetadataShape::TIMESTAMP)->toBe('/^(?=.{1,40}$)\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})$/D')
        ->and(MetadataShape::CONSOLE_KEY_ID)->toBe(ContractsMetadataShape::CONSOLE_KEY_ID)->toBe('/^[A-Za-z0-9._-]{1,64}\z/');
});

it('keeps key id validation compatible over positive boundaries and rejections', function (): void {
    foreach ([
        ['', false],
        ['a', true],
        ['K2.probe_key-id', true],
        [str_repeat('a', 64), true],
        [str_repeat('a', 65), false],
        ['has space', false],
        ['has/slash', false],
        ["control\x00character", false],
        ["valid-looking\n", false],
    ] as [$value, $expected]) {
        expect(ConsoleKeyring::isValidKeyId($value))->toBe($expected, bin2hex($value))
            ->and(ContractsConsoleKeyring::isValidKeyId($value))->toBe($expected, bin2hex($value));
    }
});

it('keeps all metadata validators compatible over positive boundaries and rejections', function (): void {
    $tables = [
        'isToken' => [
            ['', false], ['a', true], ['metadata:read', true], ['one.two_three-four', true],
            [str_repeat('a', 64), true], [str_repeat('a', 65), false], ['Uppercase', false],
            ['free text', false], ['-leading', false], ['double--separator', false], ["valid\n", false],
        ],
        'isSemver' => [
            ['', false], ['0.0.0', true], ['1.2.3-alpha.1+build.9', true],
            ['123456.123456.123456', true], ['1.2.3+'.str_repeat('a', 26), true],
            ['1.2', false], ['1.2.3-RC1', false], ['1.2.3+Jane.Operator', false],
            ['1234567.2.3', false], ['1.2.3+'.str_repeat('a', 27), false], ["1.2.3\n", false],
        ],
        'isTimestamp' => [
            ['', false], ['2026-09-26T12:34:56Z', true], ['2026-09-26 12:34:56+0000', true],
            ['2026-09-26T12:34:56.123456+00:00', true], ['SATURDAY', false],
            ['2026/09/26T12:34:56Z', false], ['2026-09-26T12-34-56Z', false],
            ['2026-09-26T12:34:56', false], ["2026-09-26T12:34:56Z\n", false],
        ],
        'isConsoleKeyId' => [
            ['', false], ['a', true], ['K2.probe_key-id', true], [str_repeat('a', 64), true],
            [str_repeat('a', 65), false], ['has space', false], ['has/slash', false],
            ["control\x1fcharacter", false], ["valid-looking\n", false],
        ],
    ];

    foreach ($tables as $method => $rows) {
        foreach ($rows as [$value, $expected]) {
            expect(MetadataShape::$method($value))->toBe($expected, $method.' '.bin2hex($value))
                ->and(ContractsMetadataShape::$method($value))->toBe($expected, $method.' '.bin2hex($value));
        }
    }
});

it('keeps burn and ownership hashes byte exact', function (): void {
    foreach ([
        ['', '', 'b7253e58e2d26fc2ceb4d2e9353b212cb6efdb1b3f28d864bd5a4f5afbafb5c9'],
        ['ab', 'c', '9bbb33969db99dd7e992e031e20eaa8725ee1a952cfcf4b18dc8f08401e85315'],
        ['a', 'bc', '867a71549b28cb98f4273a3e747ed8a52d9d2cb57f598722129877121297d721'],
        ['https://issuer.example', 'mint-123', '41ce6ef3c57a28a540a29af1478f37bfb8ae8b534f22955ce7da69974a86496d'],
    ] as [$issuer, $mintId, $expected]) {
        expect(AssertionBurn::mintHash($issuer, $mintId))->toBe($expected)
            ->and(ContractsAssertionBurn::mintHash($issuer, $mintId))->toBe($expected);
    }

    foreach ([
        ['', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
        ['abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'],
        ["abc\x00", 'dc1114cd074914bd872cc1f9a23ec910ea2203bc79779ab2e17da25782a624fc'],
    ] as [$token, $expected]) {
        expect(OwnershipClaim::hashToken($token))->toBe($expected)
            ->and(ContractsOwnershipClaim::hashToken($token))->toBe($expected);
    }
});

it('keeps all old public contract FQCNs and runtime-heavy BfC classes', function (): void {
    foreach ([
        BuiltForCloud::class,
        ConsoleKeyring::class,
        AssertionVerifier::class,
        AssertionBurn::class,
        VitalsPayload::class,
        MetadataShape::class,
        OwnershipClaim::class,
    ] as $class) {
        expect(class_exists($class))->toBeTrue($class);
    }

    foreach ([Classification::class, ConsoleRole::class, AssertionPurpose::class] as $enum) {
        expect(enum_exists($enum))->toBeTrue($enum);
    }

    expect(is_subclass_of(AssertionBurn::class, Model::class))->toBeTrue()
        ->and(is_subclass_of(OwnershipClaim::class, Model::class))->toBeTrue()
        ->and(method_exists(ConsoleKeyring::class, 'add'))->toBeTrue()
        ->and(method_exists(ConsoleKeyring::class, 'verificationKey'))->toBeTrue()
        ->and(method_exists(AssertionVerifier::class, 'verify'))->toBeTrue()
        ->and(method_exists(VitalsPayload::class, 'toArray'))->toBeTrue();
});
