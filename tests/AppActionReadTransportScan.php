<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\Audit\AppActionEvent;
use ArtisanBuild\BuiltForCloud\Audit\AppActionEventBuilder;
use ArtisanBuild\BuiltForCloud\Audit\AppActionLedgerBuilder;
use ArtisanBuild\BuiltForCloud\Audit\AppActionOutboxEntry;
use ArtisanBuild\BuiltForCloud\Audit\AppActionRecorder;
use FilesystemIterator;
use Illuminate\Routing\Route;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use ReflectionClass;
use SplFileInfo;
use Throwable;

/**
 * The contract's **"this release provides no read transport for the
 * app-action stream"**, held against what a route REACHES rather than
 * against how its URI is spelled.
 *
 * WHY IT IS NOT THE PREVIOUS CHECK. The pin this replaces matched
 * registered URIs against `/app.?action|audit/i` and asserted the set
 * was empty. Its positive control mounted `/bfc/console/app-actions`
 * and watched the regex report it — which proves the regex works, not
 * that the claim holds. **A package controller at `/bfc/console/events`
 * listing `AppActionEvent` rows was invisible to it, and the contract's
 * sentence stayed green.** A name the author chooses is not evidence
 * about what the code does, and this build has now been bitten twice by
 * a check that decides on a spelling.
 *
 * WHAT IT DECIDES ON. `tests/ConsoleChromeRouteScan.php` is the
 * precedent: classify on evidence the route itself carries, so moving
 * or renaming it changes nothing. Here the evidence is REACHABILITY —
 * from a route's action class, through the package classes that class
 * names in code, transitively, to the stream itself.
 *
 * **IT CLASSIFIES, IT DOES NOT FILTER**, and that is a statement about
 * this method rather than about routes in general: {@see classify()} is
 * handed an iterable of routes and returns one bucket for each of them,
 * instead of selecting a subset by name or prefix first. What it is
 * handed is the caller's business, and what a bucket MEANS is bounded
 * by the walk:
 *
 *  - {@see READS} — the walk reaches {@see AppActionEvent},
 *    {@see AppActionOutboxEntry}, either of their builders, or either
 *    table name, by some path other than the emission door.
 *  - {@see EMITS} — it reaches {@see AppActionRecorder} and nothing
 *    further. The recorder is where the walk STOPS rather than a class
 *    it passes through, and that is the whole distinction the bucket
 *    rests on: `POST /bfc/console/enter` reaches the stream on purpose,
 *    to write one event, and a scan that could not tell writing from
 *    reading would either report the door as a read transport or have
 *    to exempt it by name — and an exemption on the one route that
 *    legitimately touches the stream is exactly the blind spot this
 *    exists to prevent.
 *  - {@see UNRELATED} — the walk reached neither. It is also where a
 *    route lands when the walk could not follow it: a closure action,
 *    an unloadable class, or a read through a collaborator outside
 *    `src/`. **A route here has not been shown to be unrelated to the
 *    stream; it has been shown not to reach it by a path this walk
 *    follows.**
 *
 * What licenses stopping at the recorder is that its verbs do not read
 * the stream, and that is a separate fact asserted two ways in
 * `tests/AppActionAuditTest.php`, because one of them is not enough:
 *
 *  - "pins the emission door's public surface, so a verb cannot be
 *    ADDED to it unnoticed" pins the method names and the return types.
 *    It detects an ADDITION and nothing more — the bodies are not read,
 *    so a `record()` keeping its name, signature and return type while
 *    querying and returning an existing row leaves it green.
 *  - "runs no read against the stream on either of the emission door's
 *    verbs" is the behavioural half that covers that: each verb is
 *    executed with the connection's query log on and its SELECTs
 *    against the two tables are counted, with a real read through the
 *    same harness as the control. **The query log is what it reads, so
 *    a read issued directly on the PDO handle is outside it** — a
 *    tripwire over the ordinary spelling, not a proof about every way a
 *    row can be fetched.
 *
 * Both speak of the verbs that exist today. Neither says anything about
 * a verb somebody adds, which is what the surface pin is for; the two
 * are meant to be read together.
 *
 * **THE RESIDUE, named rather than implied.** This is a textual walk
 * over class names and table names, so:
 *
 *  - **An indirectly named class or table is not followed.** A helper
 *    that builds its class name from a string, reads it from config,
 *    resolves it out of the container by an alias, or queries
 *    `DB::table('bfc_app_'.'action_events')` reaches the stream and is
 *    not seen here. Closing that means data-flow analysis, which is a
 *    new instrument making a new claim and needing its own proof; this
 *    package has already withdrawn one general instrument for that
 *    reason.
 *  - **The walk follows PACKAGE class names only.** The names it can
 *    resolve are the classes under `src/`, so a package route
 *    delegating to a collaborator the host application supplies reads
 *    the stream through a class this walk cannot follow, and is
 *    reported {@see UNRELATED}. That bound is asserted where it lands,
 *    in `tests/AppActionAuditTest.php` — "names a route that reads the
 *    app-action stream under a name that mentions neither" — over a
 *    fixture route that does exactly this. It is the right scope for
 *    the sentence being held, which is about what this release ships,
 *    and it is still a bound rather than a boundary.
 *  - **A route whose action is a CLOSURE** has no class to walk from
 *    and is classified {@see UNRELATED}. No package route uses one
 *    today — read off the route group by hand, and **nothing checks
 *    that it stays true**, which makes this a caveat resting on a fact
 *    with no test behind it rather than on a property.
 *  - **MIDDLEWARE AND BLADE VIEWS ARE NOT WALKED.** The walk starts at
 *    a route's ACTION class, so the nine middleware classes every
 *    package route carries, and any view a route renders, are not
 *    considered as paths to the stream at all. A read placed in
 *    middleware reaches the rows and is reported nowhere here. That is
 *    a real gap and a bigger change than this scan; it is a debt row,
 *    not a thing this class quietly covers.
 *  - **A HOST APPLICATION's own routes** are not this package's to
 *    enumerate. The contract's sentence is about what this release
 *    ships; an app that writes its own listing over its own tables has
 *    built a read transport, and says so in its own code.
 *  - **Nothing here reads what a route RETURNS.** A route that reaches
 *    the models to count them, and serves no row, is reported as
 *    {@see READS} — deliberately, because "it only counts" is a claim
 *    about a response body that this walk cannot check and a later
 *    revision can quietly widen.
 */
final class AppActionReadTransportScan
{
    /** The walk reaches the stream by some path other than the door. */
    public const string READS = 'reads';

    /** The walk reaches the emission door and stops there. */
    public const string EMITS = 'emits';

    /** The walk reached neither, or could not be followed at all. */
    public const string UNRELATED = 'unrelated';

    /** The namespace a package class is recognised by. */
    public const string PACKAGE_NAMESPACE = 'ArtisanBuild\\BuiltForCloud\\';

    /**
     * The stream itself: the two models, their builders, and the two
     * table names. Table names are in the set because a raw query
     * reaches the rows without naming a model.
     *
     * @var list<string>
     */
    public const array STREAM = [
        AppActionEvent::class,
        AppActionOutboxEntry::class,
        AppActionEventBuilder::class,
        AppActionLedgerBuilder::class,
        'bfc_app_action_events',
        'bfc_app_action_outbox',
    ];

    /**
     * The one sanctioned way in, and the walk's terminus.
     *
     * @var list<string>
     */
    public const array EMISSION_DOOR = [AppActionRecorder::class];

    /**
     * Every registered route, keyed as `METHOD[,METHOD] /uri`, with its
     * bucket.
     *
     * @param  iterable<Route>  $routes
     * @param  array<string, string>|null  $classes  short name => fully qualified; the package's own when null
     * @return array<string, string>
     */
    public static function classify(iterable $routes, ?array $classes = null): array
    {
        $classified = [];

        foreach ($routes as $route) {
            $classified[self::name($route)] = self::bucketFor(self::actionClass($route), $classes);
        }

        ksort($classified);

        return $classified;
    }

    /**
     * The routes that reach the stream other than through the door —
     * the finding this scan exists for, each as `METHOD /uri`.
     *
     * @param  iterable<Route>  $routes
     * @param  array<string, string>|null  $classes  short name => fully qualified; the package's own when null
     * @return list<string>
     */
    public static function readTransportsIn(iterable $routes, ?array $classes = null): array
    {
        $reads = array_keys(array_filter(
            self::classify($routes, $classes),
            static fn (string $bucket): bool => $bucket === self::READS,
        ));

        sort($reads);

        return $reads;
    }

    /**
     * The bucket one action class falls into.
     *
     * A class that cannot be loaded, or a route with no class at all,
     * is {@see UNRELATED} — it is still counted, which is the property
     * that matters, and the residue says a closure is not followed.
     *
     * @param  array<string, string>|null  $classes  short name => fully qualified; the package's own when null
     */
    public static function bucketFor(?string $class, ?array $classes = null): string
    {
        if ($class === null) {
            return self::UNRELATED;
        }

        $reached = self::reachableFrom($class, $classes);

        foreach (self::STREAM as $target) {
            if (isset($reached[$target])) {
                return self::READS;
            }
        }

        foreach (self::EMISSION_DOOR as $door) {
            if (isset($reached[$door])) {
                return self::EMITS;
            }
        }

        return self::UNRELATED;
    }

    /**
     * Every package class name and stream table name reachable from one
     * class by following the names its CODE contains, transitively.
     *
     * The door is recorded and not walked into: the recorder names the
     * models, so following it would make every emitter look like a
     * reader and force the one legitimate route onto an exemption list.
     *
     * Comments are stripped before matching, for the reason every walk
     * in this suite strips them: this package discusses the stream in
     * prose throughout, and a raw search would report the explanations
     * as reaches.
     *
     * @param  array<string, string>|null  $classes  short name => fully qualified; the package's own when null
     * @return array<string, true>
     */
    public static function reachableFrom(string $class, ?array $classes = null): array
    {
        $classes ??= self::packageClasses();

        $reached = [];
        $pending = [$class];

        while ($pending !== []) {
            $current = array_pop($pending);

            if (isset($reached[$current])) {
                continue;
            }

            $reached[$current] = true;

            if (in_array($current, self::EMISSION_DOOR, true)) {
                continue;
            }

            foreach (self::namesIn(self::codeOf($current), $classes) as $name) {
                if (! isset($reached[$name])) {
                    $pending[] = $name;
                }
            }
        }

        unset($reached[$class]);

        return $reached;
    }

    /**
     * The package class names and stream table names one file's CODE
     * mentions.
     *
     * Class names are matched by their SHORT name against the classes
     * this package autoloads, so an import, a `::class` constant, a type
     * hint and a `new` all count alike and a fully qualified name and an
     * imported one are one thing.
     *
     * **CASE-INSENSITIVELY, BECAUSE PHP CLASS NAMES ARE.** The first
     * revision matched case-sensitively, so
     * `\artisanbuild\builtforcloud\audit\appactionevent::query()->get()`
     * — a spelling PHP resolves to the model and executes — reached the
     * stream and was reported as reaching nothing. Table names are
     * matched the same way, since the identifier case a database folds
     * is the database's business and not something to decide here.
     *
     * The cost is over-matching: a short name that also occurs as an
     * ordinary identifier in some other casing is counted as a
     * reference. That direction fails loud — it reports a route as
     * reading when it does not — which is the side to be wrong on.
     *
     * @param  array<string, string>|null  $classes  short name => fully qualified; the package's own when null
     * @return list<string>
     */
    public static function namesIn(string $code, ?array $classes = null): array
    {
        $found = [];

        foreach ($classes ?? self::packageClasses() as $short => $fullyQualified) {
            if (preg_match('/\b'.preg_quote($short, '/').'\b/i', $code) === 1) {
                $found[$fullyQualified] = true;
            }
        }

        foreach (self::STREAM as $target) {
            if (! str_contains($target, '\\') && stripos($code, $target) !== false) {
                $found[$target] = true;
            }
        }

        return array_keys($found);
    }

    /**
     * Every class this package autoloads, as short name => fully
     * qualified. Built from the class map on disk rather than from
     * declared classes, so a class nothing has loaded yet is still a
     * name the walk can follow.
     *
     * @return array<string, string>
     */
    public static function packageClasses(): array
    {
        static $classes = null;

        if ($classes !== null) {
            return $classes;
        }

        $classes = [];
        $root = dirname(__DIR__).'/src';

        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
        );

        /** @var SplFileInfo $file */
        foreach ($files as $file) {
            if (! $file->isFile() || $file->getExtension() !== 'php') {
                continue;
            }

            $relative = substr($file->getPathname(), strlen($root) + 1);
            $namespace = str_replace('/', '\\', dirname($relative));

            $classes[$file->getBasename('.php')] = self::PACKAGE_NAMESPACE
                .($namespace === '.' ? '' : $namespace.'\\')
                .$file->getBasename('.php');
        }

        ksort($classes);

        return $classes;
    }

    /**
     * One class's code with every comment replaced by a space, or an
     * empty string when the class has no file this walk can read.
     */
    public static function codeOf(string $class): string
    {
        if (! class_exists($class) && ! interface_exists($class) && ! trait_exists($class) && ! enum_exists($class)) {
            return '';
        }

        try {
            $file = (new ReflectionClass($class))->getFileName();
        } catch (Throwable) {
            return '';
        }

        if ($file === false || ! is_file($file)) {
            return '';
        }

        return implode('', array_map(
            static fn (array|string $token): string => is_string($token)
                ? $token
                : (in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true) ? ' ' : $token[1]),
            token_get_all((string) file_get_contents($file)),
        ));
    }

    /**
     * The class a route's action points at, or null for a closure or a
     * name that resolves to none.
     */
    public static function actionClass(Route $route): ?string
    {
        $action = $route->getActionName();
        $class = str_contains($action, '@') ? (string) strstr($action, '@', true) : $action;

        return $class !== '' && class_exists($class) ? $class : null;
    }

    private static function name(Route $route): string
    {
        $methods = array_values(array_diff($route->methods(), ['HEAD', 'OPTIONS']));

        return implode(',', $methods).' /'.$route->uri();
    }
}
