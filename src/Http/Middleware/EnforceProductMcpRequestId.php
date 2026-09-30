<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use SensitiveParameter;
use Symfony\Component\HttpFoundation\Response;

/** Reject oversized JSON-RPC ids before any product MCP route middleware can reflect them. */
final class EnforceProductMcpRequestId
{
    /** @param Closure(Request): Response $next */
    public function handle(#[SensitiveParameter] Request $request, Closure $next): Response
    {
        $payload = $request->json()->all();
        $encoded = array_key_exists('id', $payload)
            ? json_encode($payload['id'], JSON_UNESCAPED_UNICODE)
            : null;

        if (! is_string($encoded) || strlen($encoded) <= AuthenticateMcp::MAX_JSON_RPC_ID_BYTES) {
            return $next($request);
        }

        return response()->json([
            'jsonrpc' => '2.0',
            'id' => null,
            'error' => [
                'code' => -32600,
                'message' => 'Invalid Request',
            ],
        ], Response::HTTP_BAD_REQUEST);
    }
}
