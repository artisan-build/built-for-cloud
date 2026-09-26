<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;
use ArtisanBuild\BuiltForCloud\LandingManifest;
use ArtisanBuild\BuiltForCloud\UiCredentialPurposes;

it('publishes the exact conservative manifest credential and ui schema', function (): void {
    $published = require __DIR__.'/../config/built-for-cloud.php';

    expect($published['manifest'])->toBe([
        'name' => null,
        'slug' => null,
        'description' => null,
        'icon' => null,
        'product_url' => null,
    ])->and($published['credentials']['app_purposes'])->toBe([])
        ->and($published['ui'])->toBe([
            'landing_page' => false,
            'member_management' => false,
            'personal_credentials' => false,
            'installation_credentials' => false,
            'session_management' => false,
            'managed_transitions' => false,
            'credential_purposes' => [],
        ]);
});

it('retains valid credential-purpose display order and resolves submissions through the mapper', function (): void {
    config([
        'built-for-cloud.credentials.app_purposes' => [
            'reel.publish' => CredentialPurpose::Mcp->value,
            'hone.ingest' => CredentialPurpose::Consumption->value,
        ],
        'built-for-cloud.ui.credential_purposes' => ['reel.publish', 'hone.ingest'],
    ]);

    $purposes = app(UiCredentialPurposes::class);

    expect($purposes->displayed())->toBe(['reel.publish', 'hone.ingest'])
        ->and($purposes->purposeForSubmission('reel.publish'))->toBe(CredentialPurpose::Mcp)
        ->and($purposes->purposeForSubmission('hone.ingest'))->toBe(CredentialPurpose::Consumption);
});

it('omits invalid credential-purpose configuration and refuses its submission', function (mixed $configured, array $mappings, string $submitted): void {
    config([
        'built-for-cloud.credentials.app_purposes' => $mappings,
        'built-for-cloud.ui.credential_purposes' => $configured,
    ]);

    $purposes = app(UiCredentialPurposes::class);

    expect($purposes->displayed())->toBe([])
        ->and(fn () => $purposes->purposeForSubmission($submitted))
        ->toThrow(InvalidCredentialInput::class);
})->with([
    'missing list' => [null, ['hone.ingest' => CredentialPurpose::Consumption->value], 'hone.ingest'],
    'wrong list type' => ['hone.ingest', ['hone.ingest' => CredentialPurpose::Consumption->value], 'hone.ingest'],
    'wrong member type' => [[7], [], '7'],
    'list-valued member' => [[['hone.ingest']], [], 'hone.ingest'],
    'duplicate member' => [['hone.ingest', 'hone.ingest'], ['hone.ingest' => CredentialPurpose::Consumption->value], 'hone.ingest'],
    'malformed member' => [['Hone Ingest'], ['Hone Ingest' => CredentialPurpose::Consumption->value], 'Hone Ingest'],
    'unmapped member' => [['hone.ingest'], [], 'hone.ingest'],
    'list-valued mapping' => [['hone.ingest'], ['hone.ingest' => [CredentialPurpose::Consumption->value]], 'hone.ingest'],
    'unknown package purpose' => [['hone.ingest'], ['hone.ingest' => 'not-a-purpose'], 'hone.ingest'],
    'reserved signing root' => [['hone.ingest'], ['hone.ingest' => CredentialPurpose::SigningRoot->value], 'hone.ingest'],
]);

it('accepts a complete valid landing manifest', function (): void {
    config(['built-for-cloud.manifest' => [
        'name' => 'Test App',
        'slug' => 'test-app',
        'description' => 'A test-created app.',
        'icon' => 'https://assets.example.test/icon.svg',
        'product_url' => 'https://scalpels.app/products/test-app',
    ]]);

    expect(LandingManifest::fromConfiguration())->toEqual(new LandingManifest(
        name: 'Test App',
        slug: 'test-app',
        description: 'A test-created app.',
        icon: 'https://assets.example.test/icon.svg',
        productUrl: 'https://scalpels.app/products/test-app',
    ));
});

it('derives the app image Scalpels publishes from the manifest slug', function (): void {
    $manifest = new LandingManifest(
        name: 'Test App',
        slug: 'test-app',
        description: 'A test-created app.',
        icon: 'https://assets.example.test/icon.svg',
        productUrl: 'https://scalpels.app/products/test-app',
    );

    expect($manifest->imageUrl())->toBe('https://scalpels.app/img/products/transparent/test-app.png');
});

it('refuses a missing empty or non-string landing manifest field', function (string $field, mixed $replacement, bool $remove): void {
    $manifest = [
        'name' => 'Test App',
        'slug' => 'test-app',
        'description' => 'A test-created app.',
        'icon' => 'https://assets.example.test/icon.svg',
        'product_url' => 'https://scalpels.app/products/test-app',
    ];

    if ($remove) {
        unset($manifest[$field]);
    } else {
        $manifest[$field] = $replacement;
    }

    config(['built-for-cloud.manifest' => $manifest]);

    expect(fn () => LandingManifest::fromConfiguration())->toThrow(RuntimeException::class, "[{$field}]");
})->with(function (): array {
    $vectors = [];

    foreach (['name', 'slug', 'description', 'icon', 'product_url'] as $field) {
        $vectors["missing {$field}"] = [$field, null, true];
        $vectors["empty {$field}"] = [$field, '  ', false];
        $vectors["non-string {$field}"] = [$field, 7, false];
    }

    return $vectors;
});

it('refuses malformed landing manifest constraints', function (string $field, string $value): void {
    $manifest = [
        'name' => 'Test App',
        'slug' => 'test-app',
        'description' => 'A test-created app.',
        'icon' => 'https://assets.example.test/icon.svg',
        'product_url' => 'https://scalpels.app/products/test-app',
    ];
    $manifest[$field] = $value;
    config(['built-for-cloud.manifest' => $manifest]);

    expect(fn () => LandingManifest::fromConfiguration())->toThrow(RuntimeException::class, "[{$field}]");
})->with([
    'uppercase slug' => ['slug', 'Test-App'],
    'underscore slug' => ['slug', 'test_app'],
    'relative icon' => ['icon', '/icon.svg'],
    'http icon' => ['icon', 'http://assets.example.test/icon.svg'],
    'relative product url' => ['product_url', '/products/test-app'],
    'http product url' => ['product_url', 'http://scalpels.app/products/test-app'],
    'foreign product host' => ['product_url', 'https://example.test/products/test-app'],
    'lookalike product host' => ['product_url', 'https://scalpels.app.example.test/products/test-app'],
]);
