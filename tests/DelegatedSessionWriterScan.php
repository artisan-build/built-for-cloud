<?php

declare(strict_types=1);

namespace ArtisanBuild\BuiltForCloud\Tests;

use ArtisanBuild\BuiltForCloud\Console\ConsoleSession;
use ArtisanBuild\BuiltForCloud\Testing\NoSigningPathScan;
use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * The executable half of the package-wide minting guarantee: **only
 * `ConsoleGuard::redeem()` writes delegated session state anywhere in
 * `src/`.**
 *
 * WHY A SCAN AND NOT A LIST OF METHOD NAMES. That guarantee was cited by
 * three tests that could not express it: one asserted a FIXED LIST of
 * method names is absent from the guard, one asserted `ConsoleSession`
 * has no writer, and one tampered with a token. Adding a differently
 * named writer — a new class, a new method — leaves all three green
 * while falsifying the guarantee. A fixed list cannot express a
 * package-wide negative; an ENUMERATION can, and that is the same shape
 * the two scans already in this PR use
 * ({@see NoSigningPathScan} and
 * {@see NoGlobalAuthMutationScan}).
 *
 * TWO QUESTIONS, because they fail differently.
 * {@see scanWriters()} answers "which files can WRITE a delegated
 * session key" — the set must be exactly the one permitted writer.
 * {@see scanReferences()} answers "which files touch those keys at all",
 * which catches a new reader too: a second place deciding what a
 * delegated claim means is the divergence hazard this package has
 * already deleted twice.
 *
 * COMMENTS ARE STRIPPED BEFORE ANYTHING IS MATCHED, for the same reason
 * the repoint scan strips them: these keys are named in prose throughout
 * this package, and a raw search would report the explanations.
 *
 * WHAT IT DOES NOT COVER, stated so a green result is not read as more
 * than it is:
 *
 *  - **A key assembled at runtime.** `'bfc_console.'.$suffix` names no
 *    needle. So does a key that arrives in a variable from a file the
 *    scan does not flag — though {@see KEY_NEEDLES} includes
 *    `ConsoleSession::keys(`, so the ordinary way of iterating them is
 *    caught.
 *  - **The guard's own LOGIN key**, which is derived from Laravel's
 *    `SessionGuard::getName()` and is not one of these constants. That
 *    is deliberate rather than an omission: a session carrying the login
 *    key and NO claims is refused by the guard, so the claims are the
 *    load-bearing half — `tests/ConsoleActingPrincipalTest.php`
 *    ("refuses a delegated session whose claims cannot be read") drives
 *    that, and `ConsoleGuard::getName()` is public but read-only.
 *  - **Code outside `src/`.** Anything that can write the session store
 *    can assemble a session; {@see ConsoleSession}
 *    states that boundary, and this package's own tests rely on it.
 *
 * It catches the way a writer would actually be added, which is what an
 * anti-drift check is for: it exists to fail on the ordinary
 * reintroduction, not to defeat someone deliberately hiding one.
 */
final class DelegatedSessionWriterScan
{
    /**
     * The ONE file permitted to write a delegated session key, relative
     * to the scanned root.
     */
    public const string PERMITTED_WRITER = 'Console/ConsoleGuard.php';

    /**
     * Everything that names one of the four claim keys: the literals as
     * they are defined, the constants as they are used, and the accessor
     * that hands the whole set out.
     *
     * @var list<string>
     */
    public const array KEY_NEEDLES = [
        'bfc_console.assertion_issued_at',
        'bfc_console.display_name',
        'bfc_console.role',
        'bfc_console.on_behalf_of',
        '::ASSERTION_ISSUED_AT',
        '::DISPLAY_NAME',
        '::ON_BEHALF_OF',
        '::ROLE',
        'ConsoleSession::keys(',
    ];

    /**
     * Session mutators. A file is a WRITER when it contains one of these
     * AND names a key — either alone is innocent, since this package
     * reads the keys in two places and writes nothing else into a
     * session.
     *
     * @var list<string>
     */
    public const array WRITE_NEEDLES = [
        '->put(',
        '->replace(',
        '->merge(',
        '->push(',
        '->flash(',
        '->now(',
        '->flashInput(',
    ];

    /**
     * The key names a file mentions, in a stable order.
     *
     * @return list<string>
     */
    public static function referencesIn(string $contents): array
    {
        return self::matches(self::withoutComments($contents), self::KEY_NEEDLES);
    }

    /**
     * The session mutators a file uses, but only when it also names one
     * of the keys — that combination is what makes it a writer.
     *
     * @return list<string>
     */
    public static function writersIn(string $contents): array
    {
        $code = self::withoutComments($contents);

        if (self::matches($code, self::KEY_NEEDLES) === []) {
            return [];
        }

        return self::matches($code, self::WRITE_NEEDLES);
    }

    /**
     * Every file under the root that can write a delegated session key,
     * keyed by relative path and NAMING the mutators it uses.
     *
     * @return array<string, list<string>>
     */
    public static function scanWriters(string $root): array
    {
        return self::walk($root, static fn (string $contents): array => self::writersIn($contents));
    }

    /**
     * Every file under the root that names a delegated session key at
     * all, readers included.
     *
     * @return array<string, list<string>>
     */
    public static function scanReferences(string $root): array
    {
        return self::walk($root, static fn (string $contents): array => self::referencesIn($contents));
    }

    /**
     * How many PHP files the walk visited — the floor that stops a
     * scanner which enumerated nothing from reporting "clean".
     */
    public static function countPhpFiles(string $root): int
    {
        return count(iterator_to_array(self::phpFiles($root)));
    }

    /**
     * @param  callable(string): list<string>  $inspect
     * @return array<string, list<string>>
     */
    private static function walk(string $root, callable $inspect): array
    {
        $found = [];

        foreach (self::phpFiles($root) as $relativePath => $file) {
            $hits = $inspect((string) file_get_contents($file->getPathname()));

            if ($hits !== []) {
                $found[$relativePath] = $hits;
            }
        }

        ksort($found);

        return $found;
    }

    /**
     * @param  list<string>  $needles
     * @return list<string>
     */
    private static function matches(string $code, array $needles): array
    {
        return array_values(array_filter(
            $needles,
            static fn (string $needle): bool => str_contains($code, $needle),
        ));
    }

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
