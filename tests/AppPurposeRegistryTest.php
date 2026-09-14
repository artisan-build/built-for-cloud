<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\AppPurposeRegistry;
use ArtisanBuild\BuiltForCloud\CredentialPurpose;
use ArtisanBuild\BuiltForCloud\Exceptions\InvalidCredentialInput;

it('maps each app operation to exactly one closed protocol purpose', function (string $appPurpose, CredentialPurpose $expected): void {
    config(['built-for-cloud.credentials.app_purposes' => [
        'hone.ingest' => CredentialPurpose::Consumption->value,
        'hone.mcp' => CredentialPurpose::Mcp->value,
        'crate.release.audit' => CredentialPurpose::DashboardMetadata->value,
    ]]);

    expect(app(AppPurposeRegistry::class)->purpose($appPurpose))->toBe($expected);
})->with([
    ['hone.ingest', CredentialPurpose::Consumption],
    ['hone.mcp', CredentialPurpose::Mcp],
    ['crate.release.audit', CredentialPurpose::DashboardMetadata],
]);

it('fails closed with one value-free typed refusal for every invalid mapping', function (mixed $mappings, string $appPurpose): void {
    config(['built-for-cloud.credentials.app_purposes' => $mappings]);

    try {
        app(AppPurposeRegistry::class)->purpose($appPurpose);
        test()->fail('Expected the app purpose mapping to be refused.');
    } catch (InvalidCredentialInput $exception) {
        expect($exception->getMessage())->toBe('The app purpose mapping is invalid.')
            ->not->toContain('configured-sensitive-value', $appPurpose);
    }
})->with([
    'missing key' => [[], 'hone.ingest'],
    'malformed id' => [['hone.ingest' => CredentialPurpose::Consumption->value], 'Hone/ingest'],
    'non-array map' => ['configured-sensitive-value', 'hone.ingest'],
    'non-string scalar' => [['hone.ingest' => 1], 'hone.ingest'],
    'list-valued entry' => [['hone.ingest' => [CredentialPurpose::Consumption->value]], 'hone.ingest'],
    'unknown enum value' => [['hone.ingest' => 'configured-sensitive-value'], 'hone.ingest'],
]);

it('is independent of every ui affordance for both results and refusals', function (): void {
    config(['built-for-cloud.credentials.app_purposes' => [
        'hone.ingest' => CredentialPurpose::Consumption->value,
        'hone.unknown' => 'not-a-protocol-purpose',
    ]]);

    $observed = [];

    foreach ([
        ['managed_transitions' => false, 'labels' => [], 'order' => []],
        ['managed_transitions' => true, 'labels' => ['hone.ingest' => 'Ingest'], 'order' => ['hone.ingest']],
    ] as $ui) {
        config(['built-for-cloud.ui' => $ui]);

        try {
            app(AppPurposeRegistry::class)->purpose('hone.unknown');
            test()->fail('Expected the unknown protocol purpose to be refused.');
        } catch (InvalidCredentialInput $exception) {
            $observed[] = [
                app(AppPurposeRegistry::class)->purpose('hone.ingest'),
                $exception::class,
                $exception->getMessage(),
            ];
        }
    }

    expect($observed[0])->toBe($observed[1]);
});
