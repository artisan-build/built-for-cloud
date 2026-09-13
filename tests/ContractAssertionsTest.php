<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\Credential;
use ArtisanBuild\BuiltForCloud\OperatorAbility;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\SubjectType;
use ArtisanBuild\BuiltForCloud\Testing\ContractAssertions;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Queue;
use PHPUnit\Framework\AssertionFailedError;

uses(RefreshDatabase::class);
uses(ContractAssertions::class);

beforeEach(function (): void {
    Queue::fake();
});

it('passes the reusable built for cloud contract suite against the package harness', function (): void {
    $this->assertBuiltForCloudContract();
});

it('preserves the public token helpers on the unified credential store', function (): void {
    $admin = $this->mintBuiltForCloudAdminToken();
    $consume = $this->mintBuiltForCloudConsumeToken();

    $adminCredential = Credential::query()->where('secret_hash', hash('sha256', $admin))->firstOrFail();
    $consumeCredential = Credential::query()->where('secret_hash', hash('sha256', $consume))->firstOrFail();

    expect($adminCredential->subject_type)->toBe(SubjectType::Operator)
        ->and($adminCredential->abilities)->toBe([OperatorAbility::ADMIN])
        ->and($consumeCredential->subject_type)->toBe(SubjectType::ExternalConsumer)
        ->and($consumeCredential->abilities)->toBe([Scope::Consume->value]);
});

it('exercises the consumer thin-host conformance wrapper', function (): void {
    $this->assertBuiltForCloudThinHostSources(__DIR__.'/Fixtures/ThinHost');

    expect(fn () => $this->assertBuiltForCloudThinHostSources(__DIR__.'/Fixtures/RogueHost'))
        ->toThrow(AssertionFailedError::class);
});
