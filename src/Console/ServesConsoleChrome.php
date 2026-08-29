<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Console;

use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureConsoleSession;

/**
 * The marker a CONSOLE CHROME route's action carries (Console PRD D11 /
 * D14).
 *
 * It declares nothing and enforces nothing on its own. It exists so that
 * "is this a chrome route?" can be answered by asking the ROUTE what it
 * points at, rather than by matching its URI or its name — and that
 * distinction is the whole reason the interface is here. A scan that
 * recognised chrome routes by a `/bfc/console/` prefix or a `chrome`
 * substring would report clean for a chrome route mounted anywhere else,
 * which is exactly how a route pin has failed on this build before.
 *
 * WHAT IT IS USED FOR. `tests/ConsoleChromeRouteScan.php` enumerates the
 * registered routes, classifies each by whether its action implements
 * this interface, and requires every one that does to carry BOTH halves
 * of D14's seam: the guard scoping (`auth:bfc-console`, which makes the
 * console guard the guard of the request) AND
 * {@see EnsureConsoleSession} (`bfc.console`, which turns a dead
 * delegated session into the structured re-entry 401 the chrome's
 * interceptor branches on). A chrome route carrying only the first
 * renders nothing for a capped operator and never tells their browser to
 * go and re-enter.
 *   Pinned by `tests/ConsoleChromeRouteTest.php` — "requires both halves
 *   of the delegated seam on every registered chrome route" and "names a
 *   chrome route that carries only one half of the seam, and one that
 *   carries neither".
 *
 * THE RESIDUE, named because a marker is a convention and not a
 * language guarantee: an action that renders console chrome without
 * implementing this interface is invisible to that scan, and so is
 * anything an APPLICATION mounts — this package cannot enumerate a host
 * app's routes. What bounds the second one is that the chrome itself is
 * built from the resolved {@see ActingPrincipal} and renders nothing at
 * all unless that resolution is delegated, so an app route that forgets
 * the seam gets a page with no chrome rather than a page with somebody
 * else's.
 *   Pinned by `tests/ConsoleChromeTest.php` — "renders zero console
 *   chrome for a local authenticated session".
 */
interface ServesConsoleChrome {}
