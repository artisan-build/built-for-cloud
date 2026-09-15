<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud;

/** Tracks execution inside the package's system-authority entries and attributed MCP requests. */
final class SystemAuthorityContext
{
    private int $nextToken = 0;

    /** @var array<int, true> */
    private array $activeTokens = [];

    public function active(): bool
    {
        return $this->activeTokens !== [];
    }

    public function enter(): int
    {
        $token = ++$this->nextToken;
        $this->activeTokens[$token] = true;

        return $token;
    }

    public function leave(int $token): void
    {
        unset($this->activeTokens[$token]);
    }

    /**
     * @template T
     *
     * @param  callable(): T  $callback
     * @return T
     */
    public function run(callable $callback): mixed
    {
        $token = $this->enter();

        try {
            return $callback();
        } finally {
            $this->leave($token);
        }
    }
}
