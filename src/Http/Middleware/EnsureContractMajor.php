<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Middleware;

use ArtisanBuild\BuiltForCloud\BuiltForCloud;
use ArtisanBuild\BuiltForCloud\HttpContract;
use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/** Admit only the package's current, canonically encoded HTTP contract major. */
final class EnsureContractMajor
{
    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $values = $request->headers->all(HttpContract::MAJOR_HEADER);

        if ($values === []) {
            return $this->refuse('missing_contract_major', 400);
        }

        $value = count($values) === 1 ? $values[0] : null;

        if (! is_string($value) || preg_match('/^(?:0|[1-9][0-9]*)$/D', $value) !== 1) {
            return $this->refuse('malformed_contract_major', 400);
        }

        if ($value !== (string) BuiltForCloud::API_VERSION) {
            return $this->refuse('unsupported_contract_major', 426);
        }

        return $next($request);
    }

    private function refuse(string $error, int $status): JsonResponse
    {
        $response = response()->json([
            'error' => $error,
            'supported_contract_major' => BuiltForCloud::API_VERSION,
        ], $status);
        $response->headers->set('Cache-Control', 'no-store');

        return $response;
    }
}
