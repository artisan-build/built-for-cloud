<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Testing\ContractAssertions;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class, ContractAssertions::class);

it('proves MCP product admission through the reusable consumer helper', function (): void {
    $this->assertBuiltForCloudMcpProductAdmission();
});
