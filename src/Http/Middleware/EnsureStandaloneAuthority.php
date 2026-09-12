<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Middleware;

use ArtisanBuild\BuiltForCloud\AuthorityMode;
use ArtisanBuild\BuiltForCloud\AuthorityState;
use ArtisanBuild\BuiltForCloud\InstallationAuthority;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Symfony\Component\HttpFoundation\Response;

final class EnsureStandaloneAuthority
{
    /** @param Closure(Request): Response $next */
    public function handle(Request $request, Closure $next): Response
    {
        if ($request->isMethodSafe()) {
            $this->assertStandalone(InstallationAuthority::current());

            return $next($request);
        }

        return DB::transaction(function () use ($request, $next): Response {
            $row = DB::table('bfc_authority')
                ->where('key', InstallationAuthority::KEY)
                ->sharedLock()
                ->first(['mode', 'generation']);
            $this->assertStandalone(is_object($row)
                ? AuthorityState::fromRaw((string) $row->mode, (int) $row->generation)
                : AuthorityState::fromRaw('', 0));

            return $next($request);
        }, 3);
    }

    private function assertStandalone(AuthorityState $authority): void
    {
        if (! $authority->isValid() || $authority->mode !== AuthorityMode::Standalone) {
            abort(404);
        }
    }
}
