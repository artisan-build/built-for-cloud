<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ReflectionClass;
use ReflectionMethod;
use ReflectionNamedType;
use ReflectionType;
use ReflectionUnionType;

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

    /** @return list<string> */
    public static function canonicalUserBindings(string $class): array
    {
        $bindings = [];

        foreach ((new ReflectionClass($class))->getMethods(ReflectionMethod::IS_PUBLIC) as $method) {
            if ($method->getDeclaringClass()->getName() !== $class) {
                continue;
            }

            foreach ($method->getParameters() as $parameter) {
                if (self::containsCanonicalUser($parameter->getType())) {
                    $bindings[] = $class.'::'.$method->getName().'($'.$parameter->getName().')';
                }
            }

            if (self::containsCanonicalUser($method->getReturnType())) {
                $bindings[] = $class.'::'.$method->getName().'():return';
            }
        }

        sort($bindings);

        return $bindings;
    }

    private static function containsCanonicalUser(?ReflectionType $type): bool
    {
        if ($type instanceof ReflectionNamedType) {
            return $type->getName() === 'ArtisanBuild\\BuiltForCloud\\User';
        }

        if ($type instanceof ReflectionUnionType) {
            foreach ($type->getTypes() as $member) {
                if (self::containsCanonicalUser($member)) {
                    return true;
                }
            }
        }

        return false;
    }
}
