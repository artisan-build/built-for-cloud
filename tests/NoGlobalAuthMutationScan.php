<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\Testing\NoSigningPathScan;
use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * The executable half of one claim: **this package never mutates
 * process-global auth state.** It calls no `AuthManager` mutator and
 * writes `auth.defaults.guard` nowhere.
 *
 * That is a claim about ABSENCE, which nothing enforces on its own — one
 * `shouldUse()` in a later PR and the sentence in {@see ConsoleGuard}'s
 * docblock, the contract doc and the release note all quietly become
 * false. Worse, the thing that would become false is the half of the
 * scoping story this package actually owns: `auth:bfc-console` mutates
 * the default guard and the RUNTIME contains it, so a second, unsandboxed
 * mutation from inside the package would sit outside every mechanism
 * that makes the first one safe.
 *
 * IT DELIBERATELY DOES NOT SHIP, unlike its sibling
 * {@see NoSigningPathScan}, which
 * lives in `src/Testing` precisely so a consuming app can hold the same
 * line over its own tree. The rule here is not one an application should
 * adopt: `shouldUse()` is perfectly correct in application code, and
 * Laravel's own middleware calls it. It is a rule for THIS package, so
 * it lives with this package's tests.
 *
 * Living in `tests/` also means the scanner is never inside the tree it
 * walks, so — unlike the signing scan — it needs no split literals to
 * avoid reporting itself.
 *
 * COMMENTS ARE STRIPPED BEFORE ANYTHING IS MATCHED. This package's
 * docblocks name `shouldUse()` repeatedly, explaining at length why it
 * does not call it; a raw string search would report every one of those
 * explanations as an offence, and the test would end up being about its
 * own prose.
 *
 * READS ARE NOT OFFENCES. `config('auth.defaults.guard')` is exactly what
 * {@see ActingPrincipalResolver} must do — that key IS the route's
 * applicable guard — so only the WRITE forms are matched.
 */
final class NoGlobalAuthMutationScan
{
    /**
     * The `AuthManager` methods that repoint the default guard. Matched
     * by name: there is no legitimate call to any of them from this
     * package, through the facade or an injected manager alike.
     *
     * @var list<string>
     */
    public const array MUTATORS = ['shouldUse', 'resolveUsersUsing', 'setDefaultDriver'];

    /**
     * The two shapes a direct config write takes. Deliberately not the
     * bare key, which every legitimate READ also contains.
     *
     * @var list<string>
     */
    public const array CONFIG_WRITES = ["auth.defaults.guard' =>", "set('auth.defaults.guard'"];

    /**
     * Every offence in one file's CODE, in a stable order.
     *
     * @return list<string>
     */
    public static function offencesIn(string $contents): array
    {
        $code = self::withoutComments($contents);

        $offences = [];

        foreach ([...self::MUTATORS, ...self::CONFIG_WRITES] as $needle) {
            if (str_contains($code, $needle)) {
                $offences[] = $needle;
            }
        }

        return $offences;
    }

    /**
     * Walk a tree and collect every offending PHP file, keyed by its
     * path relative to the root.
     *
     * @return array<string, list<string>>
     */
    public static function scan(string $root): array
    {
        $offenders = [];

        foreach (self::phpFiles($root) as $relativePath => $file) {
            $offences = self::offencesIn((string) file_get_contents($file->getPathname()));

            if ($offences !== []) {
                $offenders[$relativePath] = $offences;
            }
        }

        ksort($offenders);

        return $offenders;
    }

    /**
     * How many PHP files the walk actually visited — the floor that
     * stops a scanner which enumerated nothing from reporting "clean".
     */
    public static function countPhpFiles(string $root): int
    {
        return count(iterator_to_array(self::phpFiles($root)));
    }

    /**
     * The file's code with every comment and doc comment replaced by a
     * space, so a mention in prose can never read as a call.
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
