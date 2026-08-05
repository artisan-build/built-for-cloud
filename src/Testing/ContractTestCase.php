<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use Illuminate\Foundation\Testing\TestCase;

abstract class ContractTestCase extends TestCase
{
    use ContractAssertions;
}
