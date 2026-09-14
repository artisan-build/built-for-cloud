<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use InvalidArgumentException;
use RuntimeException;

/** Builds verdicts only by executing a probe for each closed-vocabulary case. */
final class P6GateRecorder
{
    /** @var array<string, string> */
    private array $verdicts = [];

    /** @param list<string> $expected */
    public function __construct(private readonly array $expected)
    {
        if ($expected === [] || count(array_unique($expected)) !== count($expected)) {
            throw new InvalidArgumentException('The P6c observed case inventory is invalid.');
        }
    }

    public function observe(string $case, callable $probe): void
    {
        if (! in_array($case, $this->expected, true) || array_key_exists($case, $this->verdicts)) {
            throw new InvalidArgumentException("The P6c case [{$case}] is unknown or already observed.");
        }

        if ($probe() !== true) {
            throw new RuntimeException("The P6c case [{$case}] did not produce a passing observation.");
        }

        $this->verdicts[$case] = 'pass';
    }

    /** @return array<string, string> */
    public function completed(): array
    {
        $ordered = [];
        foreach ($this->expected as $case) {
            if (($this->verdicts[$case] ?? null) !== 'pass') {
                throw new RuntimeException("The P6c case [{$case}] was not observed.");
            }

            $ordered[$case] = 'pass';
        }

        return $ordered;
    }
}
