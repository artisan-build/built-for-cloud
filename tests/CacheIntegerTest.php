<?php

declare(strict_types=1);

use ArtisanBuild\BuiltForCloud\Support\CacheInteger;

it('parses only canonical non-negative cache integers', function (mixed $value, ?int $expected): void {
    expect(CacheInteger::parse($value))->toBe($expected);
})->with([
    'integer' => [12, 12],
    'numeric string' => ['12', 12],
    'zero' => ['0', 0],
    'leading zero' => ['012', null],
    'trailing junk' => ['12a', null],
    'leading whitespace' => [' 12', null],
    'negative' => ['-1', null],
    'negative integer' => [-1, null],
    'exponent' => ['1e3', null],
    'float' => ['1.0', null],
    'leading plus' => ['+12', null],
    'integer overflow' => [PHP_INT_MAX.'0', null],
]);
