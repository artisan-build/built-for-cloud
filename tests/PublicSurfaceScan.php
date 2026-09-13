<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\Console\DelegatedActor;
use ArtisanBuild\BuiltForCloud\User;
use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use ReflectionClass;
use ReflectionIntersectionType;
use ReflectionMethod;
use ReflectionNamedType;
use ReflectionType;
use ReflectionUnionType;
use RuntimeException;
use SplFileInfo;

/**
 * The second half of the minting guarantee: **no new PUBLIC METHOD may
 * appear on a class that can reach the delegated session writer without
 * somebody saying so in the diff.**
 *
 * WHY THIS EXISTS, and it is the third form the same claim has taken.
 * "Only `redeem()` mints a delegated session" was first cited by tests
 * naming a FIXED LIST of absent methods — a differently named writer
 * escaped it. It was then pinned by
 * {@see DelegatedSessionWriterScan}, a FILE enumeration — and a
 * differently named PUBLIC METHOD on the one permitted file escapes
 * that, because it can simply call the existing private
 * `ConsoleGuard::beginSession()` while every file assertion stays green.
 * The scan enumerated files; the guarantee is about reachable
 * operations.
 *
 * So this enumerates the reachable operations. Adding a public method to
 * `ConsoleGuard` reds the suite, and whoever adds it has to extend the
 * expected set in the same diff — which is the point: not prevention,
 * which PHP cannot give, but a change that cannot be made silently.
 *
 * WHAT IT CANNOT DO, said here rather than left to be discovered. PHP
 * cannot express "no future public method may call this private method"
 * as a language guarantee, so this is a tripwire and not a lock. It
 * does not see a change to `redeem()`'s OWN body (the token tests cover
 * that), nor reflection into a private method, nor anything outside
 * `src/`. {@see DelegatedSessionWriterScan} states the rest of the
 * uncovered surface; the two are meant to be read together.
 */
final class PublicSurfaceScan
{
    /**
     * Every public method a class declares, sorted, including
     * `__construct`.
     *
     * @return list<string>
     */
    public static function of(string $class): array
    {
        $methods = array_map(
            static fn (ReflectionMethod $method): string => $method->getName(),
            (new ReflectionClass($class))->getMethods(ReflectionMethod::IS_PUBLIC),
        );

        sort($methods);

        return array_values($methods);
    }

    /**
     * Public methods the class has that the expected set does not — the
     * escape this scan exists to name.
     *
     * @param  list<string>  $expected
     * @return list<string>
     */
    public static function unexpectedIn(string $class, array $expected): array
    {
        return array_values(array_diff(self::of($class), $expected));
    }

    /**
     * Public methods the expected set names that the class no longer
     * has. A REMOVAL is drift too: if `redeem()` vanished, the guarantee
     * would still read as true while meaning something else entirely.
     *
     * @param  list<string>  $expected
     * @return list<string>
     */
    public static function missingFrom(string $class, array $expected): array
    {
        return array_values(array_diff($expected, self::of($class)));
    }

    /** @return list<string> */
    public static function declaredBy(string $class): array
    {
        $methods = array_map(
            static fn (ReflectionMethod $method): string => $method->getName(),
            array_filter(
                (new ReflectionClass($class))->getMethods(ReflectionMethod::IS_PUBLIC),
                static fn (ReflectionMethod $method): bool => $method->getDeclaringClass()->getName() === $class,
            ),
        );
        sort($methods);

        return array_values($methods);
    }

    /**
     * Derive every declared public method before applying any binding
     * classification. The source root is never inferred from a class list.
     *
     * @param  list<string>  $additionalRoots
     * @return list<array{class: class-string, method: string, file: string, line: int, parameters: list<array{name: string, types: list<string>}>, returnTypes: list<string>}>
     */
    public static function discoverDeclaredPublicMethods(string $sourceRoot, array $additionalRoots = []): array
    {
        $packageRoot = dirname($sourceRoot);
        $surface = [];

        foreach ([$sourceRoot, ...$additionalRoots] as $root) {
            foreach (self::phpFiles($root) as $file) {
                $contents = file_get_contents($file->getPathname());

                if (! is_string($contents)) {
                    throw new RuntimeException("Could not read [{$file->getPathname()}].");
                }

                if (preg_match('/^namespace\s+([^;]+);/m', $contents, $namespace) !== 1
                    || preg_match('/^\s*(?:(?:final|abstract|readonly)\s+)*(?:class|interface|trait|enum)\s+([A-Z][A-Za-z0-9_]*)\b/m', $contents, $symbol) !== 1) {
                    continue;
                }

                $class = $namespace[1].'\\'.$symbol[1];
                $reflection = new ReflectionClass($class);

                foreach ($reflection->getMethods(ReflectionMethod::IS_PUBLIC) as $method) {
                    if ($method->getDeclaringClass()->getName() !== $class) {
                        continue;
                    }

                    $parameters = [];

                    foreach ($method->getParameters() as $parameter) {
                        $parameters[] = [
                            'name' => $parameter->getName(),
                            'types' => self::typeNames($parameter->getType()),
                        ];
                    }

                    $surface[] = [
                        'class' => $class,
                        'method' => $method->getName(),
                        'file' => ltrim(substr($file->getPathname(), strlen($packageRoot)), DIRECTORY_SEPARATOR),
                        'line' => $method->getStartLine(),
                        'parameters' => $parameters,
                        'returnTypes' => self::typeNames($method->getReturnType()),
                    ];
                }
            }
        }

        usort($surface, static fn (array $left, array $right): int => [
            $left['class'],
            $left['method'],
        ] <=> [
            $right['class'],
            $right['method'],
        ]);

        return $surface;
    }

    /**
     * Exact executable predicate: report a public method with two distinct
     * parameters whose declared types can carry the canonical User and a
     * DelegatedActor, or a DelegatedActor parameter whose return type can carry
     * the canonical User. Named union/intersection members, subclasses and
     * parent interfaces such as Authenticatable are included. Untyped values
     * and method-body or ORM-relation inference are deliberately outside the
     * bound.
     *
     * @param  list<array{class: class-string, method: string, file: string, line: int, parameters: list<array{name: string, types: list<string>}>, returnTypes: list<string>}>  $surface
     * @return list<string>
     */
    public static function canonicalUserBindings(array $surface): array
    {
        $bindings = [];

        foreach ($surface as $method) {
            $canonical = [];
            $delegated = [];

            foreach ($method['parameters'] as $index => $parameter) {
                if (self::typesCarry($parameter['types'], User::class)) {
                    $canonical[$index] = $parameter['name'];
                }

                if (self::typesCarry($parameter['types'], DelegatedActor::class)) {
                    $delegated[$index] = $parameter['name'];
                }
            }

            foreach ($canonical as $canonicalIndex => $canonicalName) {
                $delegatedIndex = array_key_first(array_diff_key($delegated, [$canonicalIndex => true]));

                if ($delegatedIndex === null) {
                    continue;
                }

                $bindings[] = sprintf(
                    '%s:%d [%s::%s($%s,$%s)]',
                    $method['file'],
                    $method['line'],
                    $method['class'],
                    $method['method'],
                    $canonicalName,
                    $delegated[$delegatedIndex],
                );

                continue 2;
            }

            if (self::typesCarry($method['returnTypes'], User::class) && $delegated !== []) {
                $bindings[] = sprintf(
                    '%s:%d [%s::%s($%s):return]',
                    $method['file'],
                    $method['line'],
                    $method['class'],
                    $method['method'],
                    array_values($delegated)[0],
                );
            }
        }

        sort($bindings);

        return $bindings;
    }

    /** @return list<string> */
    private static function typeNames(?ReflectionType $type): array
    {
        if ($type instanceof ReflectionNamedType) {
            return [$type->getName()];
        }

        if ($type instanceof ReflectionUnionType || $type instanceof ReflectionIntersectionType) {
            $names = [];

            foreach ($type->getTypes() as $member) {
                array_push($names, ...self::typeNames($member));
            }

            return array_values(array_unique($names));
        }

        return [];
    }

    /** @param list<string> $types */
    private static function typesCarry(array $types, string $identity): bool
    {
        foreach ($types as $type) {
            if ((class_exists($type) || interface_exists($type))
                && (is_a($identity, $type, true) || is_a($type, $identity, true))) {
                return true;
            }
        }

        return false;
    }

    /** @return iterable<SplFileInfo> */
    private static function phpFiles(string $root): iterable
    {
        if (is_file($root)) {
            yield new SplFileInfo($root);

            return;
        }

        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
        );

        /** @var SplFileInfo $file */
        foreach ($files as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                yield $file;
            }
        }
    }
}
