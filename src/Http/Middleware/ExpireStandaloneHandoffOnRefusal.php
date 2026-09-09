<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Middleware;

use ArtisanBuild\BuiltForCloud\StandaloneHandoff;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;

final readonly class ExpireStandaloneHandoffOnRefusal
{
    public function __construct(private StandaloneHandoff $handoff) {}

    /** @param Closure(Request): Response $next */
    public function handle(Request $request, Closure $next): Response
    {
        $this->handoff->beginRequest();

        try {
            $response = $next($request);
        } catch (HttpExceptionInterface $exception) {
            if ($exception->getStatusCode() !== Response::HTTP_NOT_FOUND) {
                throw $exception;
            }

            $response = response('', Response::HTTP_NOT_FOUND);
        }

        if ($response->getStatusCode() === Response::HTTP_NOT_FOUND
            && ($purpose = $this->handoff->purposeForRoute($request->route()?->getName())) !== null) {
            $this->handoff->expire($purpose);
        }

        return $response;
    }
}
