<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Testing;

use Laravel\Mcp\Server;
use Laravel\Mcp\Server\Tool;

/** @internal */
final class McpDelegatedEnforcementState
{
    /** @var array<class-string<Server>, list<class-string<Tool>>> */
    private array $servers = [];

    /**
     * @param  class-string<Server>  $serverClass
     * @param  list<class-string<Tool>>  $tools
     */
    public function record(string $serverClass, array $tools): void
    {
        $this->servers[$serverClass] = $tools;
    }

    /** @param class-string<Server> $serverClass */
    public function forget(string $serverClass): void
    {
        unset($this->servers[$serverClass]);
    }

    /**
     * @param  class-string<Server>  $serverClass
     * @return list<class-string<Tool>>|null
     */
    public function toolsFor(string $serverClass): ?array
    {
        return $this->servers[$serverClass] ?? null;
    }
}
