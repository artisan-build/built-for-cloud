<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Mcp;

use Illuminate\Container\Container;
use Illuminate\Http\Request;
use Laravel\Mcp\Exceptions\JsonRpcException;

/**
 * Filters Laravel MCP tool registration against the current request's ceiling.
 * Undeclared effects fail closed as destructive, and a targeted above-ceiling
 * call receives the bounded policy refusal without invoking the tool.
 *
 * Pinned by `tests/McpEffectCeilingTest.php` — "neither lists nor calls a
 * write tool through the read door", "treats an undeclared tool as destructive
 * rather than read" and "distinguishes an above ceiling refusal from a
 * genuinely absent tool".
 *
 * @phpstan-ignore trait.unused (the supported seam for consuming products and conformance fixtures)
 */
trait RespectsEffectCeiling
{
    /**
     * @throws JsonRpcException
     */
    public function eligibleForRegistration(): bool
    {
        if (method_exists($this, 'shouldRegister')
            && ! (bool) Container::getInstance()->call([$this, 'shouldRegister'])) {
            return false;
        }

        $request = app('request');
        $ceiling = $request instanceof Request ? RequestEffectCeiling::current($request) : null;
        $effect = ToolEffect::of($this)?->value ?? Effect::Destructive;

        if ($ceiling === null || ! $ceiling->allows($effect)) {
            if ($request instanceof Request) {
                $this->refuseTargetedCall($request);
            }

            return false;
        }

        return true;
    }

    /**
     * Laravel MCP normally collapses an ineligible tool into tool-not-found.
     * Preserve that behavior for other eligibility checks, but identify this
     * policy refusal when the above-ceiling tool is the requested call target.
     *
     * @throws JsonRpcException
     */
    private function refuseTargetedCall(Request $request): void
    {
        $payload = $request->json()->all();
        $params = $payload['params'] ?? null;

        if (($payload['method'] ?? null) !== 'tools/call'
            || ! is_array($params)
            || ($params['name'] ?? null) !== $this->name()) {
            return;
        }

        $requestId = $payload['id'] ?? null;

        throw new JsonRpcException(
            RequestEffectCeiling::REFUSAL_MESSAGE,
            RequestEffectCeiling::REFUSAL_CODE,
            is_string($requestId) || is_int($requestId) ? $requestId : null,
        );
    }
}
