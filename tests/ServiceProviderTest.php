<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Contracts\UsageReporter;
use ArtisanBuild\BuiltForCloud\NullUsageReporter;
use ArtisanBuild\BuiltForCloud\PassThroughPayloadFilter;
use ArtisanBuild\BuiltForCloud\TokenGenerator;
use ArtisanBuild\BuiltForCloudContracts\OutboundPayload;
use ArtisanBuild\BuiltForCloudContracts\PayloadDisposition;
use ArtisanBuild\BuiltForCloudContracts\PayloadFilter;

it('registers package configuration', function (): void {
    expect(config('built-for-cloud.token_prefix'))->toBe('tok_')
        ->and(config('built-for-cloud.cloud.binary'))->toBe('cloud');
});

it('binds the surviving usage reporter contract to its null implementation', function (): void {
    $reporter = app(UsageReporter::class);

    expect($reporter)->toBeInstanceOf(NullUsageReporter::class)
        ->and($reporter->perToken())->toBe([]);
});

it('binds the payload filter contract to its pass-through implementation', function (): void {
    $payload = new OutboundPayload('assay', 'run.step', 1, PayloadDisposition::Droppable, ['usage' => 10], []);
    $filter = app(PayloadFilter::class);

    expect($filter)->toBeInstanceOf(PassThroughPayloadFilter::class)
        ->and($filter->filter($payload))->toBe($payload);
});

it('generates plaintext with the configured prefix and its matching sha256 hash', function (): void {
    config(['built-for-cloud.token_prefix' => 'configured_']);

    $generated = (new TokenGenerator)->generate();

    expect($generated->plaintext)->toStartWith('configured_')
        ->and($generated->hash)->toBe(hash('sha256', $generated->plaintext));
});
