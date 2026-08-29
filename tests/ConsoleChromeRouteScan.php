<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\Console\ConsoleGuardConfiguration;
use ArtisanBuild\BuiltForCloud\Console\ServesConsoleChrome;
use ArtisanBuild\BuiltForCloud\Http\Middleware\EnsureConsoleSession;
use FilesystemIterator;
use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Routing\Route;
use Illuminate\Routing\Router;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * D14's TWO SEAMS, enumerated over the routes that are actually
 * registered: **a console route carries the guard scoping AND the
 * session middleware, or it is named here.**
 *
 * The two are not interchangeable and neither implies the other.
 * `auth:bfc-console` is Laravel's own middleware and is what makes the
 * console guard the guard OF THE REQUEST, so it decides who the request
 * acts as and therefore what chrome renders. {@see EnsureConsoleSession}
 * (`bfc.console`) is what turns a dead delegated session into the
 * STRUCTURED re-entry 401 the chrome's interceptor branches on. A route
 * with only the first renders nothing for a capped operator and never
 * tells their browser to go and re-enter; a route with only the second
 * answers re-entry for a request whose principal was resolved through
 * somebody else's guard.
 *
 * **IT CLASSIFIES, IT DOES NOT FILTER — and that distinction is the
 * whole design.** A scan that selected "the console routes" by URI
 * prefix or by name and then checked those could never see a console
 * route mounted somewhere else, which is precisely how a route pin on
 * this build has failed before: a check that filters or aggregates
 * BEFORE comparing cannot see a MISSING thing. So {@see classify()}
 * visits EVERY registered route and puts each into exactly one bucket,
 * on evidence the route itself carries:
 *
 *  - {@see CHROME} — its action implements {@see ServesConsoleChrome}.
 *    This is a fact about the class the route points at, not about how
 *    the route is spelled, so moving the route or renaming its path
 *    changes nothing.
 *  - {@see DELEGATED} — it carries at least one half of the seam. This
 *    is what catches the inverse: a route nobody marked as chrome that
 *    has nonetheless been given `bfc.console` alone.
 *  - {@see UNRELATED} — neither. It is still enumerated, so the counts
 *    add up and a route cannot vanish from the scan by being
 *    unrecognised.
 *
 * Everything in the first two buckets must carry BOTH halves, and
 * {@see orderBreaksIn()} additionally requires them in the right ORDER
 * once Laravel has sorted the stack — a distinct property, and the one
 * that caught a live defect in this very PR.
 *   Pinned by `tests/ConsoleChromeRouteTest.php` — "requires both halves
 *   of the delegated seam on every registered chrome route", "names a
 *   chrome route that carries only one half of the seam, and one that
 *   carries neither" and "names a route whose throttle hoists the guard
 *   scoping in front of the re-entry answer".
 *
 * **THE SECOND LEG, and it is what closes the hole the first leaves.**
 * The marker is a convention: a controller that renders the chrome and
 * does NOT implement it would be classified {@see UNRELATED} and pass.
 * {@see viewReferencesIn()} therefore walks `src/` for any file that
 * NAMES a `bfc::` view in code — comments stripped first, so the prose
 * in this package that discusses `bfc::layout` is not mistaken for a
 * render — and the test requires every such file to be one the diff
 * accounted for. A new controller reaching for the layout reds the
 * suite.
 *
 * **THE RESIDUE, named rather than implied.** Three things are outside
 * what this can see, and none of them is a package route:
 *
 *  - **A HOST APPLICATION's own routes.** This package cannot enumerate
 *    them, and the app's own pages are where `bfc::layout` is actually
 *    extended. What bounds that is not this scan but the chrome itself:
 *    it is built from the resolved acting principal and renders nothing
 *    unless that resolution is delegated, so an app route that forgets
 *    the seam gets a page with no chrome rather than a page wearing
 *    somebody else's identity.
 *  - **Middleware reached through a GROUP.** {@see Route::gatherMiddleware()}
 *    reports what the route and its controller declare, not what a
 *    named group expands to, so a package route that got its seam from
 *    inside a group would be reported as missing it. That direction is
 *    the safe one — it fails loud — and no package route does it.
 *  - **A chrome renderer reached by a closure**, which has no action
 *    class to carry a marker. No package route uses one; the same
 *    caveat is already recorded for the contract-document scan.
 */
final class ConsoleChromeRouteScan
{
    /** The route's action is marked as serving console chrome. */
    public const string CHROME = 'chrome';

    /** The route carries at least one half of the delegated seam. */
    public const string DELEGATED = 'delegated';

    /** Neither — enumerated anyway, so nothing leaves the scan unseen. */
    public const string UNRELATED = 'unrelated';

    /** The guard scoping half, as a route names it. */
    public const string GUARD_SCOPING = 'auth:'.ConsoleGuardConfiguration::GUARD;

    /** The session half, as a route names it. */
    public const string SESSION_MIDDLEWARE = 'bfc.console';

    /**
     * Every registered route, keyed as `METHOD[,METHOD] /uri`, with the
     * bucket it falls into.
     *
     * @param  iterable<Route>  $routes
     * @return array<string, string>
     */
    public static function classify(iterable $routes): array
    {
        $classified = [];

        foreach ($routes as $route) {
            $classified[self::name($route)] = match (true) {
                self::servesChrome($route) => self::CHROME,
                self::hasGuardScoping($route) || self::hasSessionMiddleware($route) => self::DELEGATED,
                default => self::UNRELATED,
            };
        }

        ksort($classified);

        return $classified;
    }

    /**
     * Routes whose action is marked as serving console chrome — the
     * check that this scan is looking at anything at all.
     *
     * @param  iterable<Route>  $routes
     * @return list<string>
     */
    public static function chromeRoutesIn(iterable $routes): array
    {
        $chrome = array_keys(array_filter(
            self::classify($routes),
            static fn (string $bucket): bool => $bucket === self::CHROME,
        ));

        sort($chrome);

        return array_values($chrome);
    }

    /**
     * Every route in the first two buckets that is missing a half of the
     * seam, as `METHOD /uri: missing …`.
     *
     * @param  iterable<Route>  $routes
     * @return list<string>
     */
    public static function seamBreaksIn(iterable $routes): array
    {
        $breaks = [];

        foreach ($routes as $route) {
            $bucket = match (true) {
                self::servesChrome($route) => self::CHROME,
                self::hasGuardScoping($route) || self::hasSessionMiddleware($route) => self::DELEGATED,
                default => self::UNRELATED,
            };

            if ($bucket === self::UNRELATED) {
                continue;
            }

            $missing = array_values(array_filter([
                self::hasGuardScoping($route) ? null : self::GUARD_SCOPING,
                self::hasSessionMiddleware($route) ? null : self::SESSION_MIDDLEWARE,
            ]));

            if ($missing !== []) {
                $breaks[] = self::name($route).': missing '.implode(' and ', $missing);
            }
        }

        sort($breaks);

        return array_values($breaks);
    }

    /**
     * Delegated routes whose seam is in the WRONG ORDER once Laravel has
     * sorted the stack: the guard scoping running BEFORE the session
     * middleware, as `METHOD /uri: …`.
     *
     * **THIS IS NOT A STYLE RULE AND IT CAUGHT A REAL DEFECT.** Laravel
     * re-orders a route's middleware by `$middlewarePriority`, in which
     * `AuthenticatesRequests` outranks `ThrottleRequests`. A route that
     * DECLARES `[throttle, …, bfc.console, auth:bfc-console]` — which is
     * the order every other route in this package uses, throttle
     * outermost — is EXECUTED as `[…, auth:bfc-console, throttle,
     * bfc.console]`, so a request with no delegated session meets
     * Laravel's own `AuthenticationException` before it ever reaches
     * D7's structured 401. The declared order is not the executed order,
     * and only the executed one matters.
     *
     * So this reads the SORTED, resolved stack from the router rather
     * than the route's own declaration.
     *
     * @param  iterable<Route>  $routes
     * @return list<string>
     */
    public static function orderBreaksIn(Router $router, iterable $routes): array
    {
        $breaks = [];

        foreach ($routes as $route) {
            if (! self::servesChrome($route) && ! self::hasGuardScoping($route) && ! self::hasSessionMiddleware($route)) {
                continue;
            }

            $sorted = array_values(array_filter(
                $router->gatherRouteMiddleware($route),
                static fn (mixed $middleware): bool => is_string($middleware),
            ));

            $session = self::indexOf($sorted, static fn (string $name): bool => $name === EnsureConsoleSession::class);
            $guard = self::indexOf($sorted, static fn (string $name): bool => $name === Authenticate::class);

            if ($session === null || $guard === null) {
                // A missing half is seamBreaksIn()'s finding, not this
                // one; reporting it twice would say the same thing in
                // two voices.
                continue;
            }

            if ($session > $guard) {
                $breaks[] = self::name($route).': the guard scoping runs before the re-entry answer';
            }
        }

        sort($breaks);

        return array_values($breaks);
    }

    /**
     * The index of the first entry whose middleware NAME (the part
     * before any parameters) satisfies the predicate, or null.
     *
     * @param  list<string>  $middleware
     * @param  callable(string): bool  $matches
     */
    private static function indexOf(array $middleware, callable $matches): ?int
    {
        foreach ($middleware as $index => $entry) {
            $name = strstr($entry, ':', true);

            if ($matches($name === false ? $entry : $name)) {
                return $index;
            }
        }

        return null;
    }

    /**
     * Files under `src/` that NAME a `bfc::` view in code, relative to
     * the root — the second leg, which sees a chrome renderer the marker
     * convention missed.
     *
     * Comments and doc comments are replaced before matching, for the
     * same reason every other scan in this suite does it: this package
     * discusses `bfc::layout` in prose throughout, and a raw search
     * would report the explanations.
     *
     * @return list<string>
     */
    public static function viewReferencesIn(string $root): array
    {
        $found = [];

        foreach (self::phpFiles($root) as $relative => $file) {
            $code = self::withoutComments((string) file_get_contents($file->getPathname()));

            if (str_contains($code, 'bfc::')) {
                $found[] = $relative;
            }
        }

        sort($found);

        return array_values($found);
    }

    /**
     * How many files the walk above actually visited — the floor that
     * stops a scanner which enumerated nothing from reporting "clean".
     */
    public static function countPhpFiles(string $root): int
    {
        return count(iterator_to_array(self::phpFiles($root)));
    }

    private static function servesChrome(Route $route): bool
    {
        $action = $route->getActionName();
        $class = str_contains($action, '@') ? strstr($action, '@', true) : $action;

        return is_string($class)
            && $class !== ''
            && class_exists($class)
            && is_subclass_of($class, ServesConsoleChrome::class);
    }

    /**
     * Whether the route names Laravel's own auth middleware WITH the
     * console guard. Both spellings count — the `auth:` alias and the
     * middleware class — and the guard is matched against the parameter
     * list rather than against the whole string, so `auth:bfc-console,web`
     * is recognised and `auth:bfc-console-actors` is not.
     */
    private static function hasGuardScoping(Route $route): bool
    {
        foreach (self::middleware($route) as $middleware) {
            [$name, $parameters] = array_pad(explode(':', $middleware, 2), 2, '');

            if ($name !== 'auth' && $name !== Authenticate::class) {
                continue;
            }

            if (in_array(ConsoleGuardConfiguration::GUARD, explode(',', $parameters), true)) {
                return true;
            }
        }

        return false;
    }

    private static function hasSessionMiddleware(Route $route): bool
    {
        foreach (self::middleware($route) as $middleware) {
            $name = strstr($middleware, ':', true);
            $name = $name === false ? $middleware : $name;

            if ($name === self::SESSION_MIDDLEWARE || $name === EnsureConsoleSession::class) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return list<string>
     */
    private static function middleware(Route $route): array
    {
        return array_values(array_filter(
            $route->gatherMiddleware(),
            static fn (mixed $middleware): bool => is_string($middleware),
        ));
    }

    private static function name(Route $route): string
    {
        $methods = array_values(array_diff($route->methods(), ['HEAD', 'OPTIONS']));

        return implode(',', $methods).' /'.$route->uri();
    }

    /**
     * The file's code with every comment and doc comment replaced by a
     * space, so a mention in prose can never read as a render.
     */
    private static function withoutComments(string $contents): string
    {
        return implode('', array_map(
            static fn (array|string $token): string => is_string($token)
                ? $token
                : (in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true) ? ' ' : $token[1]),
            token_get_all($contents),
        ));
    }

    /**
     * @return iterable<string, SplFileInfo>
     */
    private static function phpFiles(string $root): iterable
    {
        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
        );

        /** @var SplFileInfo $file */
        foreach ($files as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                yield substr($file->getPathname(), strlen($root) + 1) => $file;
            }
        }
    }
}
