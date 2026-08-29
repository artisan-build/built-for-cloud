<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\Console\AssertionVerifier;
use ArtisanBuild\BuiltForCloud\Http\Controllers\ConsoleEnter;
use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use ReflectionClass;
use ReflectionMethod;
use ReflectionNamedType;
use ReflectionParameter;
use SensitiveParameter;
use SplFileInfo;
use Symfony\Component\HttpFoundation\Request as SymfonyRequest;

/**
 * **A console assertion is a live admin-minting credential, and every
 * frame that holds one must be marked `#[SensitiveParameter]`.**
 *
 * WHY A SCAN AND NOT THREE ATTRIBUTES. PR3 marked
 * `ConsoleGuard::redeem()` and stopped there, which was correct for the
 * one caller that existed. PR4 then made `AssertionVerifier::verify()`
 * reachable from a NEW frame — and `verify()`, `keyIdOf()` and the
 * endpoint's own `spendAndRedeem()` were all unmarked. With
 * `zend.exception_ignore_args=0`, an ordinary setting, a database
 * failure inside the burn or a keyring lookup puts the complete
 * `v4.public…` token into the customer's own logged stack trace.
 * Marking the three the reviewer named would leave the fourth caller
 * to be found the same way, so the rule is enumerated instead.
 *
 * AND THEN IT MISSED THE FRAME THE FIX ITSELF MADE REACHABLE. The first
 * revision of this scan matched only STRING parameters named for a
 * token, which is a name rule wearing an enumeration's clothes:
 * `ConsoleEnter::__invoke(Request $request)` holds the submitted
 * assertion just as completely, `input('assertion')` returns it, and
 * the fail-closed audit added in the same round made that frame an
 * exception path. A rule that cannot say "this frame can hold the
 * credential" without being told the parameter's name is the same
 * fixed-list-versus-enumeration mistake PR3 spent rounds on.
 *
 * THE RULE, exactly. Within the scanned roots, a parameter must carry
 * `#[SensitiveParameter]` when it is either:
 *
 *  - typed `string` (or `?string`) with a NAME ENDING IN `token`,
 *    case-insensitively — narrow on purpose, since `$tokenId` and
 *    `$tokenHash` are identifiers and digests, not secrets, and neither
 *    ends in `token`; or
 *  - typed as an HTTP **request** — anything that is-a
 *    `Symfony\Component\HttpFoundation\Request`. A request object
 *    carries whatever credential the client presented, which on these
 *    routes is a console assertion or an operator bearer token. This
 *    half needs no name at all, which is the point of adding it.
 *
 * WHAT IT DOES NOT COVER, said here rather than left to be discovered:
 *
 *  - **Anything outside the scanned roots.** The rest of `src/` carries
 *    other credential-shaped parameters with their own history; this
 *    scan is about the console surfaces and says nothing about them.
 *  - **A credential held in a shape neither rule names.** `string
 *    $bytes`, an array, a DTO. A scanner cannot know what a string
 *    holds, so this stays a tripwire against the ordinary
 *    reintroduction rather than a proof about every possible shape —
 *    and the claim in the code that cites it is worded to match.
 *  - **Union and intersection types**, which are skipped rather than
 *    guessed at.
 *  - **VENDOR frames**, which are the large residue and cannot be
 *    closed from here at all: `ParagonIE\Paseto\Parser::parse()`
 *    receives the token, and the whole framework pipeline holds the
 *    `Request`. See {@see AssertionVerifier} and
 *    {@see ConsoleEnter},
 *    which state that residue and what is done about it instead.
 *  - **Local variables and closure `use` bindings**, which PHP does not
 *    put in a stack trace in the first place.
 */
final class AssertionParameterScan
{
    /**
     * The roots that make up the console assertion path, relative to
     * `src/`. A directory is walked; a file is taken as itself.
     *
     * @var list<string>
     */
    public const array ROOTS = ['Console', 'Http/Controllers/ConsoleEnter.php'];

    /** The package's PSR-4 prefix, for turning a path into a class. */
    private const string NAMESPACE_PREFIX = 'ArtisanBuild\\BuiltForCloud\\';

    /**
     * Every frame in the given classes that holds assertion bytes, as
     * `ShortClass::method($param)`, whether or not it is marked.
     *
     * @param  list<class-string>  $classes
     * @return list<string>
     */
    public static function framesIn(array $classes): array
    {
        return self::walk($classes, static fn (ReflectionParameter $parameter): bool => true);
    }

    /**
     * The frames that hold assertion bytes and are NOT marked — the
     * offence this scan exists to name.
     *
     * @param  list<class-string>  $classes
     * @return list<string>
     */
    public static function unprotectedIn(array $classes): array
    {
        return self::walk(
            $classes,
            static fn (ReflectionParameter $parameter): bool => $parameter->getAttributes(SensitiveParameter::class) === [],
        );
    }

    /**
     * The classes under the scanned roots, as fully-qualified names.
     *
     * @param  list<string>  $roots
     * @return list<class-string>
     */
    public static function classesIn(string $srcRoot, array $roots): array
    {
        $classes = [];

        foreach ($roots as $root) {
            $target = $srcRoot.'/'.$root;

            foreach (is_dir($target) ? self::phpFiles($target, $root) : [$root => $target] as $relative => $file) {
                if (! is_string($file) || ! is_file($file)) {
                    continue;
                }

                /** @var class-string $class */
                $class = self::NAMESPACE_PREFIX.str_replace(['/', '.php'], ['\\', ''], $relative);

                if (class_exists($class) || enum_exists($class) || interface_exists($class)) {
                    $classes[] = $class;
                }
            }
        }

        sort($classes);

        return array_values(array_unique($classes));
    }

    /**
     * @param  list<class-string>  $classes
     * @param  callable(ReflectionParameter): bool  $keep
     * @return list<string>
     */
    private static function walk(array $classes, callable $keep): array
    {
        $frames = [];

        foreach ($classes as $class) {
            $reflection = new ReflectionClass($class);

            foreach ($reflection->getMethods() as $method) {
                if ($method->getDeclaringClass()->getName() !== $class) {
                    continue;
                }

                foreach ($method->getParameters() as $parameter) {
                    if (self::holdsAssertionBytes($parameter) && $keep($parameter)) {
                        $frames[] = self::name($reflection, $method, $parameter);
                    }
                }
            }
        }

        sort($frames);

        return array_values($frames);
    }

    private static function holdsAssertionBytes(ReflectionParameter $parameter): bool
    {
        $type = $parameter->getType();

        if (! $type instanceof ReflectionNamedType) {
            return false;
        }

        $name = $type->getName();

        if ($name === 'string') {
            return str_ends_with(strtolower($parameter->getName()), 'token');
        }

        // A request object carries whatever the client presented. No
        // parameter name is consulted, deliberately: the frame this
        // rule exists for was called `$request`.
        return is_a($name, SymfonyRequest::class, true);
    }

    /**
     * @param  ReflectionClass<object>  $class
     */
    private static function name(ReflectionClass $class, ReflectionMethod $method, ReflectionParameter $parameter): string
    {
        return $class->getShortName().'::'.$method->getName().'($'.$parameter->getName().')';
    }

    /**
     * @return iterable<string, string>
     */
    private static function phpFiles(string $root, string $prefix): iterable
    {
        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
        );

        /** @var SplFileInfo $file */
        foreach ($files as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                $relative = substr($file->getPathname(), strlen($root) + 1);

                yield $prefix.'/'.$relative => $file->getPathname();
            }
        }
    }
}
