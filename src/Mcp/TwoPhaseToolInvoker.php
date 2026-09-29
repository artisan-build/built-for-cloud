<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Mcp;

use Generator;
use Illuminate\Container\Container;
use Laravel\Mcp\Request;
use Laravel\Mcp\Response;
use Laravel\Mcp\ResponseFactory;
use Laravel\Mcp\Server\Tool;
use Laravel\Mcp\Server\ToolInvoker;
use Laravel\Mcp\Transport\JsonRpcRequest;
use Laravel\Mcp\Transport\JsonRpcResponse;
use Traversable;
use UnexpectedValueException;

/** Invokes preview or protected handlers with confirmation removed from args. */
final class TwoPhaseToolInvoker extends ToolInvoker
{
    public function preview(Tool $tool, JsonRpcRequest $request): JsonRpcResponse
    {
        $response = $this->withRequest($request, function () use ($tool, $request): mixed {
            return $this->callHandler(
                fn (): mixed => Container::getInstance()->call([$tool, TwoPhase::PREVIEW_METHOD]),
                $request,
            );
        });

        if ($response instanceof Traversable) {
            throw new UnexpectedValueException('Two-phase previews cannot stream.');
        }

        /** @var Response|ResponseFactory|array<int, Response>|string $response */
        return $this->toJsonRpcResponse($request, $response, $this->serializable($tool));
    }

    public function protected(Tool $tool, JsonRpcRequest $request): Generator|JsonRpcResponse
    {
        return $this->withRequest($request, fn (): Generator|JsonRpcResponse => parent::invoke($tool, $request));
    }

    /**
     * @template T
     *
     * @param  callable(): T  $callback
     * @return T
     */
    private function withRequest(JsonRpcRequest $request, callable $callback): mixed
    {
        $container = Container::getInstance();
        $previous = $container->bound('mcp.request') ? $container->make('mcp.request') : null;
        $previousConcreteRequest = $container->bound(Request::class) ? $container->make(Request::class) : null;
        $current = $request->toRequest();
        $container->instance('mcp.request', $current);
        $container->instance(Request::class, $current);

        try {
            return $callback();
        } finally {
            if ($previous instanceof Request) {
                $container->instance('mcp.request', $previous);
            } else {
                $container->forgetInstance('mcp.request');
            }

            if ($previousConcreteRequest instanceof Request) {
                $container->instance(Request::class, $previousConcreteRequest);
            } else {
                $container->forgetInstance(Request::class);
            }
        }
    }
}
