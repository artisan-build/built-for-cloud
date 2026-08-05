<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\ApiToken;
use ArtisanBuild\BuiltForCloud\Scope;
use ArtisanBuild\BuiltForCloud\Testing\ContractAssertions;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Queue;

uses(RefreshDatabase::class);
uses(ContractAssertions::class);

beforeEach(function (): void {
    Queue::fake();
});

it('passes the reusable built for cloud contract suite against the package harness', function (): void {
    $this->assertBuiltForCloudContract();
});

it('provides helpers for minting contract auth tokens', function (): void {
    $admin = $this->mintBuiltForCloudAdminToken();
    $consume = $this->mintBuiltForCloudConsumeToken();

    $adminToken = ApiToken::query()->where('token_hash', hash('sha256', $admin))->firstOrFail();
    $consumeToken = ApiToken::query()->where('token_hash', hash('sha256', $consume))->firstOrFail();

    expect($adminToken->abilities)->toBe([Scope::Admin->value])
        ->and($consumeToken->abilities)->toBe([Scope::Consume->value]);
});
