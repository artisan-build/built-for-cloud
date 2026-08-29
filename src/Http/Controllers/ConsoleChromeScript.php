<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Http\Controllers;

use ArtisanBuild\BuiltForCloud\Console\ServesConsoleChrome;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureConsoleSession;
use Illuminate\Http\Response;
use RuntimeException;

/**
 * `GET /bfc/console/chrome.js` — the chrome's re-entry interceptor
 * (Console PRD D7), served as a file rather than inlined into the
 * layout.
 *
 * **WHY A ROUTE AND NOT AN INLINE `<script>`.** An inline script is
 * exactly what a Content Security Policy worth having forbids: an app
 * that has to add `'unsafe-inline'` to `script-src` so the package's
 * chrome will run has been handed a downgrade by a dependency. Served
 * from the app's own origin, the interceptor needs nothing beyond
 * `script-src 'self'`, and an app running a nonce- or hash-based policy
 * pays nothing either. `docs/http-contract.md` carries the guidance.
 *
 * **IT IS A DELEGATED SURFACE, ON THE SAME TERMS AS THE PAGE THAT LOADS
 * IT.** The route carries both halves of D14's seam — `auth:bfc-console`
 * for the guard scoping and {@see EnsureConsoleSession} for the
 * structured re-entry answer — because the chrome is delegated-only end
 * to end, and a chrome route that carried only the first would leave a
 * capped operator's session alive while rendering them nothing.
 *
 * That is scoping, not secrecy, and it is worth saying which: this
 * script is not confidential, an operator's browser can read it, and
 * nothing here would be dangerous in anyone else's hands. What the gate
 * buys is that every route this package mounts for the chrome answers on
 * the same terms, so the enumeration in
 * `tests/ConsoleChromeRouteScan.php` is a rule rather than a list of
 * exceptions.
 *   Pinned by `tests/ConsoleChromeRouteTest.php` — "requires both halves
 *   of the delegated seam on every registered chrome route".
 *
 * THE COST, stated: the response is `private, no-store`, so an
 * operator's browser re-fetches it on every page load rather than
 * caching it. A shared cache must never hold a response whose
 * availability depends on a session cookie, and a few hundred bytes per
 * page load is the honest price of that.
 *
 * **THIS CONTROLLER EMITS NO APP ACTION.** Serving an asset is not
 * something a human did, and D17's stream is for things they did; an
 * event per script fetch would be one row per page load, attributed to
 * an operator who clicked nothing.
 */
final class ConsoleChromeScript implements ServesConsoleChrome
{
    /**
     * The interceptor's source, which is a file in this package rather
     * than a string in this class: the same bytes the browser runs are
     * the ones `tests/ConsoleReentryInterceptorTest.php` executes, so
     * the tested script and the served script cannot be two things.
     */
    public const string SOURCE = __DIR__.'/../../../resources/js/console-reentry.js';

    public function __invoke(): Response
    {
        $source = file_get_contents(self::SOURCE);

        if ($source === false) {
            // The file ships inside the package; an unreadable one is a
            // broken install, not a request the caller got wrong.
            throw new RuntimeException('The built-for-cloud console re-entry script could not be read.');
        }

        return new Response($source, 200, [
            'Content-Type' => 'text/javascript; charset=utf-8',
            'Cache-Control' => 'private, no-store',
            // The bytes are static, so a client that already has them
            // can be told so without the response ever entering a
            // shared cache.
            'ETag' => '"'.substr(hash('sha256', $source), 0, 32).'"',
            'X-Content-Type-Options' => 'nosniff',
        ]);
    }
}
